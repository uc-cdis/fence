import glob
import os
import re
import subprocess as sp
import yaml
import copy
from contextlib import contextmanager
from csv import DictReader
from io import StringIO
from stat import S_ISDIR

import paramiko
from cdislogging import get_logger
from email_validator import validate_email, EmailNotValidError
from gen3authz.client.arborist.client import ArboristError
from gen3users.validation import validate_user_yaml
from paramiko.proxy import ProxyCommand
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from userdatamodel.driver import SQLAlchemyDriver

from fence.config import config
from fence.models import (
    AccessPrivilege,
    AuthorizationProvider,
    Project,
    Tag,
    User,
    query_for_user,
    Client,
)
from fence.resources.storage import StorageManager
from fence.sync import utils


def _format_policy_id(path, privilege):
    resource = ".".join(name for name in path.split("/") if name)
    return "{}-{}".format(resource, privilege)


def download_dir(sftp, remote_dir, local_dir):
    """
    Recursively download file from remote_dir to local_dir
    Args:
        remote_dir(str)
        local_dir(str)
    Returns: None
    """
    dir_items = sftp.listdir_attr(remote_dir)

    for item in dir_items:
        remote_path = remote_dir + "/" + item.filename
        local_path = os.path.join(local_dir, item.filename)
        if S_ISDIR(item.st_mode):
            download_dir(sftp, remote_path, local_path)
        else:
            sftp.get(remote_path, local_path)


def arborist_role_for_permission(permission):
    """
    For the programs/projects in the existing fence access control model, in order to
    use arborist for checking permissions we generate a policy for each combination of
    program/project and privilege. The roles involved all contain only one permission,
    for one privilege from the project access model.
    """
    return {
        "id": permission,
        "permissions": [
            {"id": permission, "action": {"service": "*", "method": permission}}
        ],
    }


@contextmanager
def _read_file(filepath, encrypted=True, key=None, logger=None):
    """
    Context manager for reading and optionally decrypting file it only
    decrypts files encrypted by unix 'crypt' tool which is used by dbGaP.

    Args:
        filepath (str): path to the file
        encrypted (bool): whether the file is encrypted

    Returns:
        Generator[file-like class]: file like object for the file
    """
    if encrypted:
        has_crypt = sp.call(["which", "mcrypt"])
        if has_crypt != 0:
            if logger:
                logger.error("Need to install mcrypt to decrypt files from dbgap")
            # TODO (rudyardrichter, 2019-01-08): raise error and move exit out to script
            exit(1)
        p = sp.Popen(
            [
                "mcrypt",
                "-a",
                "enigma",
                "-o",
                "scrypt",
                "-m",
                "stream",
                "--bare",
                "--key",
                key,
                "--force",
            ],
            stdin=open(filepath, "r"),
            stdout=sp.PIPE,
            stderr=open(os.devnull, "w"),
            universal_newlines=True,
        )
        try:
            yield StringIO(p.communicate()[0])
        except UnicodeDecodeError:
            logger.error("Could not decode file. Check the decryption key.")
    else:
        f = open(filepath, "r")
        yield f
        f.close()


class UserYAML(object):
    """
    Representation of the information in a YAML file describing user, project, and ABAC
    information for access control.
    """

    def __init__(
        self,
        projects=None,
        user_info=None,
        policies=None,
        clients=None,
        authz=None,
        project_to_resource=None,
        logger=None,
        user_abac=None,
    ):
        self.projects = projects or {}
        self.user_info = user_info or {}
        self.user_abac = user_abac or {}
        self.policies = policies or {}
        self.clients = clients or {}
        self.authz = authz or {}
        self.project_to_resource = project_to_resource or {}
        self.logger = logger

    @classmethod
    def from_file(cls, filepath, encrypted=True, key=None, logger=None):
        """
        Add access by "auth_id" to "self.projects" to update the Fence DB.
        Add access by "resource" to "self.user_abac" to update Arborist.
        """
        data = {}
        if filepath:
            with _read_file(filepath, encrypted=encrypted, key=key, logger=logger) as f:
                file_contents = f.read()
                validate_user_yaml(file_contents)  # run user.yaml validation tests
                data = yaml.safe_load(file_contents)
        else:
            if logger:
                logger.info("Did not sync a user.yaml, no file path provided.")

        projects = dict()
        user_info = dict()
        policies = dict()

        # resources should be the resource tree to construct in arborist
        user_abac = dict()

        # Fall back on rbac block if no authz. Remove when rbac in useryaml fully deprecated.
        if not data.get("authz") and data.get("rbac"):
            if logger:
                logger.info(
                    "No authz block found but rbac block present. Using rbac block"
                )
            data["authz"] = data["rbac"]

        # get user project mapping to arborist resources if it exists
        project_to_resource = data.get("authz", dict()).get(
            "user_project_to_resource", dict()
        )

        # read projects and privileges for each user
        users = data.get("users", {})
        for username, details in users.items():
            # users should occur only once each; skip if already processed
            if username in projects:
                msg = "invalid yaml file: user `{}` occurs multiple times".format(
                    username
                )
                if logger:
                    logger.error(msg)
                raise EnvironmentError(msg)

            privileges = {}
            resource_permissions = dict()
            for project in details.get("projects", {}):
                try:
                    privileges[project["auth_id"]] = set(project["privilege"])
                except KeyError as e:
                    if logger:
                        logger.error("project {} missing field: {}".format(project, e))
                    continue

                # project may not have `resource` field.
                # prefer resource field;
                # if no resource or mapping, assume auth_id is resource.
                resource = project.get("resource", project["auth_id"])

                if project["auth_id"] not in project_to_resource:
                    project_to_resource[project["auth_id"]] = resource
                resource_permissions[resource] = set(project["privilege"])

            user_info[username] = {
                "email": details.get("email", ""),
                "display_name": details.get("display_name", ""),
                "phone_number": details.get("phone_number", ""),
                "tags": details.get("tags", {}),
                "admin": details.get("admin", False),
            }
            if not details.get("email"):
                try:
                    valid = validate_email(
                        username, allow_smtputf8=False, check_deliverability=False
                    )
                    user_info[username]["email"] = valid.email
                except EmailNotValidError:
                    pass
            projects[username] = privileges
            user_abac[username] = resource_permissions

            # list of policies we want to grant to this user, which get sent to arborist
            # to check if they're allowed to do certain things
            policies[username] = details.get("policies", [])

        if logger:
            logger.info(
                "Got user project to arborist resource mapping:\n{}".format(
                    str(project_to_resource)
                )
            )

        authz = data.get("authz", dict())
        if not authz:
            # older version: resources in root, no `authz` section or `rbac` section
            if logger:
                logger.warning(
                    "access control YAML file is using old format (missing `authz`/`rbac`"
                    " section in the root); assuming that if it exists `resources` will"
                    " be on the root level, and continuing"
                )
            # we're going to throw it into the `authz` dictionary anyways, so the rest of
            # the code can pretend it's in the normal place that we expect
            resources = data.get("resources", [])
            # keep authz empty dict if resources is not specified
            if resources:
                authz["resources"] = data.get("resources", [])

        clients = data.get("clients", {})

        return cls(
            projects=projects,
            user_info=user_info,
            user_abac=user_abac,
            policies=policies,
            clients=clients,
            authz=authz,
            project_to_resource=project_to_resource,
            logger=logger,
        )


class UserSyncer(object):
    def __init__(
        self,
        dbGaP,
        DB,
        project_mapping,
        storage_credentials=None,
        db_session=None,
        is_sync_from_dbgap_server=False,
        sync_from_local_csv_dir=None,
        sync_from_local_yaml_file=None,
        arborist=None,
        folder=None,
    ):
        """
        Syncs ACL files from dbGap to auth database and storage backends
        Args:
            dbGaP: a list of dict containing creds to access dbgap sftp
            DB: database connection string
            project_mapping: a dict containing how dbgap ids map to projects
            storage_credentials: a dict containing creds for storage backends
            sync_from_dir: path to an alternative dir to sync from instead of
                           dbGaP
            arborist:
                ArboristClient instance if the syncer should also create
                resources in arborist
            folder: a local folder where dbgap telemetry files will sync to
        """
        self.sync_from_local_csv_dir = sync_from_local_csv_dir
        self.sync_from_local_yaml_file = sync_from_local_yaml_file
        self.is_sync_from_dbgap_server = is_sync_from_dbgap_server
        self.dbGaP = dbGaP
        self.parse_consent_code = dbGaP[0].get("parse_consent_code", True)
        self.session = db_session
        self.driver = SQLAlchemyDriver(DB)
        self.project_mapping = project_mapping or {}
        self._projects = dict()
        self._created_roles = set()
        self._created_policies = set()
        self._dbgap_study_to_resources = dict()
        self.logger = get_logger(
            "user_syncer", log_level="debug" if config["DEBUG"] is True else "info"
        )
        self.arborist_client = arborist
        self.folder = folder

        if storage_credentials:
            self.storage_manager = StorageManager(
                storage_credentials, logger=self.logger
            )

    @staticmethod
    def _match_pattern(filepath, encrypted=True):
        """
        Check if the filename matches dbgap access control file pattern

        Args:
            filepath (str): path to file
            encrypted (bool): whether the file is encrypted

        Returns:
            bool: whether the pattern matches
        """
        pattern = r"authentication_file_phs(\d{6}).(csv|txt)"
        if encrypted:
            pattern += ".enc"
        pattern += "$"
        return re.match(pattern, os.path.basename(filepath))

    def _get_from_sftp_with_proxy(self, server, path):
        """
        Download all data from sftp sever to a local dir

        Args:
            server (dict) : dictionary containing info to access sftp server
            path (str): path to local directory

        Returns:
            None
        """
        proxy = None
        if server.get("proxy", "") != "":
            command = "ssh -i ~/.ssh/id_rsa {user}@{proxy} nc {host} {port}".format(
                user=server.get("proxy_user", ""),
                proxy=server.get("proxy", ""),
                host=server.get("host", ""),
                port=server.get("port", 22),
            )
            self.logger.info("SSH proxy command: {}".format(command))

            proxy = ProxyCommand(command)

        with paramiko.SSHClient() as client:
            client.set_log_channel(self.logger.name)

            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            parameters = {
                "hostname": str(server.get("host", "")),
                "username": str(server.get("username", "")),
                "password": str(server.get("password", "")),
                "port": int(server.get("port", 22)),
            }
            if proxy:
                parameters["sock"] = proxy

            self.logger.info("SSH connection parameters: {}".format(parameters))
            client.connect(**parameters)
            with client.open_sftp() as sftp:
                download_dir(sftp, "./", path)

        if proxy:
            proxy.close()

    def _get_from_ftp_with_proxy(self, server, path):
        """
        Download data from ftp sever to a local dir

        Args:
            server (dict): dictionary containing information for accessing server
            path(str): path to local files

        Returns:
            None
        """
        execstr = 'lftp -u {},{}  {} -e "set ftp:proxy http://{}; mirror . {}; exit"'.format(
            server.get("username", ""),
            server.get("password", ""),
            server.get("host", ""),
            server.get("proxy", ""),
            path,
        )
        os.system(execstr)

    def _parse_csv(self, file_dict, sess, dbgap_config={}, encrypted=True):
        """
        parse csv files to python dict

        Args:
            file_dict: a dictionary with key(file path) and value(privileges)
            sess: sqlalchemy session
            dbgap_config: a dictionary containing information about the dbGaP sftp server
                (comes from fence config)
            encrypted: boolean indicating whether those files are encrypted


        Return:
            Tuple[[dict, dict]]:
                (user_project, user_info) where user_project is a mapping from
                usernames to project permissions and user_info is a mapping
                from usernames to user details, such as email

        Example:

            (
                {
                    username: {
                        'project1': {'read-storage','write-storage'},
                        'project2': {'read-storage'},
                    }
                },
                {
                    username: {
                        'email': 'email@mail.com',
                        'display_name': 'display name',
                        'phone_number': '123-456-789',
                        'tags': {'dbgap_role': 'PI'}
                    }
                },
            )

        """
        user_projects = dict()
        user_info = dict()

        # parse dbGaP sftp server information
        dbgap_key = dbgap_config.get("decrypt_key", None)
        parse_consent_code = dbgap_config.get("parse_consent_code", True)
        enable_common_exchange_area_access = dbgap_config.get(
            "enable_common_exchange_area_access", False
        )
        study_common_exchange_areas = dbgap_config.get(
            "study_common_exchange_areas", {}
        )

        if parse_consent_code and enable_common_exchange_area_access:
            self.logger.info(
                f"using study to common exchange area mapping: {study_common_exchange_areas}"
            )

        for filepath, privileges in file_dict.items():
            self.logger.info("Reading file {}".format(filepath))
            if os.stat(filepath).st_size == 0:
                self.logger.warning("Empty file {}".format(filepath))
                continue
            if not self._match_pattern(filepath, encrypted=encrypted):
                self.logger.warning(
                    "Filename {} does not match dbgap access control filename pattern;"
                    " this could mean that the filename has an invalid format, or has"
                    " an unexpected .enc extension, or lacks the .enc extension where"
                    " expected. This file is NOT being processed by usersync!".format(
                        filepath
                    )
                )
                continue

            with _read_file(
                filepath, encrypted=encrypted, key=dbgap_key, logger=self.logger
            ) as f:
                csv = DictReader(f, quotechar='"', skipinitialspace=True)
                for row in csv:
                    username = row.get("login", "")
                    if username == "":
                        continue

                    phsid_privileges = {}
                    phsid = row.get("phsid", "").split(".")
                    dbgap_project = phsid[0]
                    if len(phsid) > 1 and parse_consent_code:
                        consent_code = phsid[-1]

                        # c999 indicates full access to all consents and access
                        # to a study-specific exchange area
                        # access to at least one study-specific exchange area implies access
                        # to the parent study's common exchange area
                        #
                        # NOTE: Handling giving access to all consents is done at
                        #       a later time, when we have full information about possible
                        #       consents
                        self.logger.debug(
                            f"got consent code {consent_code} from dbGaP project "
                            f"{dbgap_project}"
                        )
                        if (
                            consent_code == "c999"
                            and enable_common_exchange_area_access
                            and dbgap_project in study_common_exchange_areas
                        ):
                            self.logger.info(
                                "found study with consent c999 and Fence "
                                "is configured to parse exchange area data. Giving user "
                                f"{username} {privileges} privileges in project: "
                                f"{study_common_exchange_areas[dbgap_project]}."
                            )
                            self._add_dbgap_project_for_user(
                                study_common_exchange_areas[dbgap_project],
                                privileges,
                                username,
                                sess,
                                user_projects,
                                dbgap_config,
                            )

                        dbgap_project += "." + consent_code

                    display_name = row.get("user name", "")
                    tags = {"dbgap_role": row.get("role", "")}

                    # some dbgap telemetry files have information about a researchers PI
                    if "downloader for" in row:
                        tags["pi"] = row["downloader for"]

                    # prefer name over previous "downloader for" if it exists
                    if "downloader for names" in row:
                        tags["pi"] = row["downloader for names"]

                    user_info[username] = {
                        "email": row.get("email", ""),
                        "display_name": display_name,
                        "phone_number": row.get("phone", ""),
                        "tags": tags,
                    }

                    if dbgap_project not in self.project_mapping:
                        self._add_dbgap_project_for_user(
                            dbgap_project,
                            privileges,
                            username,
                            sess,
                            user_projects,
                            dbgap_config,
                        )
                    for element_dict in self.project_mapping.get(dbgap_project, []):
                        try:
                            phsid_privileges = {
                                element_dict["auth_id"]: set(privileges)
                            }

                            # need to add dbgap project to arborist
                            if self.arborist_client:
                                self._add_dbgap_study_to_arborist(
                                    element_dict["auth_id"], dbgap_config
                                )

                            if username not in user_projects:
                                user_projects[username] = {}
                            user_projects[username].update(phsid_privileges)
                        except ValueError as e:
                            self.logger.info(e)
        return user_projects, user_info

    def _add_dbgap_project_for_user(
        self, dbgap_project, privileges, username, sess, user_projects, dbgap_config
    ):
        """
        Helper function for csv parsing that adds a given dbgap project to Fence/Arborist
        and then updates the dictionary containing all user's project access
        """
        if dbgap_project not in self._projects:
            self.logger.debug(
                "creating Project in fence for dbGaP study: {}".format(dbgap_project)
            )

            project = self._get_or_create(sess, Project, auth_id=dbgap_project)

            # need to add dbgap project to arborist
            if self.arborist_client:
                self._add_dbgap_study_to_arborist(dbgap_project, dbgap_config)

            if project.name is None:
                project.name = dbgap_project
            self._projects[dbgap_project] = project
        phsid_privileges = {dbgap_project: set(privileges)}
        if username in user_projects:
            user_projects[username].update(phsid_privileges)
        else:
            user_projects[username] = phsid_privileges

    @staticmethod
    def sync_two_user_info_dict(user_info1, user_info2):
        """
        Merge user_info1 into user_info2. Values in user_info2 are overriden
        by values in user_info1. user_info2 ends up containing the merged dict.

        Args:
            user_info1 (dict): nested dict
            user_info2 (dict): nested dict

            Example:
            {username: {'email': 'abc@email.com'}}

        Returns:
            None
        """
        user_info2.update(user_info1)

    @staticmethod
    def sync_two_phsids_dict(phsids1, phsids2):
        """
        Merge pshid1 into phsids2. phsids2 ends up containing the merged dict
        (see explanation below).

        Args:
            phsids1, phsids2: nested dicts mapping phsids to sets of permissions

            Example:
            {
                username: {
                    phsid1: {'read-storage','write-storage'},
                    phsid2: {'read-storage'},
                }
            }

        Return:
            None

        Explanation:
            Consider merging projects of the same user:

                {user1: {phsid1: privillege1}}

                {user1: {phsid2: privillege2}}

            case 1: phsid1 != phsid2. Output:

                {user1: {phsid1: privillege1, phsid2: privillege2}}

            case 2: phsid1 == phsid2 and privillege1! = privillege2. Output:

                {user1: {phsid1: union(privillege1, privillege2)}}

            For the other cases, just simple addition
        """
        for user, projects1 in phsids1.items():
            if not phsids2.get(user):
                phsids2[user] = projects1
            else:
                for phsid1, privilege1 in projects1.items():
                    if phsid1 not in phsids2[user]:
                        phsids2[user][phsid1] = set()
                    phsids2[user][phsid1].update(privilege1)

    def sync_to_db_and_storage_backend(self, user_project, user_info, sess):
        """
        sync user access control to database and storage backend

        Args:
            user_project (dict): a dictionary of

                {
                    username: {
                        'project1': {'read-storage','write-storage'},
                        'project2': {'read-storage'}
                    }
                }

            user_info (dict): a dictionary of {username: user_info{}}
            sess: a sqlalchemy session

        Return:
            None
        """
        self._init_projects(user_project, sess)

        auth_provider_list = [
            self._get_or_create(sess, AuthorizationProvider, name="dbGaP"),
            self._get_or_create(sess, AuthorizationProvider, name="fence"),
        ]

        cur_db_user_project_list = {
            (ua.user.username.lower(), ua.project.auth_id)
            for ua in sess.query(AccessPrivilege).all()
        }

        # we need to compare db -> whitelist case-insensitively for username.
        # db stores case-sensitively, but we need to query case-insensitively
        user_project_lowercase = {}
        syncing_user_project_list = set()
        for username, projects in user_project.items():
            user_project_lowercase[username.lower()] = projects
            for project, _ in projects.items():
                syncing_user_project_list.add((username.lower(), project))

        user_info_lowercase = {
            username.lower(): info for username, info in user_info.items()
        }

        to_delete = set.difference(cur_db_user_project_list, syncing_user_project_list)
        to_add = set.difference(syncing_user_project_list, cur_db_user_project_list)
        to_update = set.intersection(
            cur_db_user_project_list, syncing_user_project_list
        )

        # when updating users we want to maintain case sesitivity in the username so
        # pass the original, non-lowered user_info dict
        self._upsert_userinfo(sess, user_info)
        self._revoke_from_storage(to_delete, sess)
        self._revoke_from_db(sess, to_delete)
        self._grant_from_storage(to_add, user_project_lowercase, sess)
        self._grant_from_db(
            sess,
            to_add,
            user_info_lowercase,
            user_project_lowercase,
            auth_provider_list,
        )

        # re-grant
        self._grant_from_storage(to_update, user_project_lowercase, sess)
        self._update_from_db(sess, to_update, user_project_lowercase)

        self._validate_and_update_user_admin(sess, user_info_lowercase)

        sess.commit()

    def _revoke_from_db(self, sess, to_delete):
        """
        Revoke user access to projects in the auth database

        Args:
            sess: sqlalchemy session
            to_delete: a set of (username, project.auth_id) to be revoked from db
        Return:
            None
        """
        for (username, project_auth_id) in to_delete:
            q = (
                sess.query(AccessPrivilege)
                .filter(AccessPrivilege.project.has(auth_id=project_auth_id))
                .join(AccessPrivilege.user)
                .filter(func.lower(User.username) == username)
                .all()
            )
            for access in q:
                self.logger.info(
                    "revoke {} access to {} in db".format(username, project_auth_id)
                )
                sess.delete(access)

    def _validate_and_update_user_admin(self, sess, user_info):
        """
        Make sure there is no admin user that is not in yaml/csv files

        Args:
            sess: sqlalchemy session
            user_info: a dict of
            {
                username: {
                    'email': email,
                    'display_name': display_name,
                    'phone_number': phonenum,
                    'tags': {'k1':'v1', 'k2': 'v2'}
                    'admin': is_admin
                }
            }
        Returns:
            None
        """
        for admin_user in sess.query(User).filter_by(is_admin=True).all():
            if admin_user.username.lower() not in user_info:
                admin_user.is_admin = False
                sess.add(admin_user)
                self.logger.info(
                    "remove admin access from {} in db".format(
                        admin_user.username.lower()
                    )
                )

    def _update_from_db(self, sess, to_update, user_project):
        """
        Update user access to projects in the auth database

        Args:
            sess: sqlalchemy session
            to_update:
                a set of (username, project.auth_id) to be updated from db

        Return:
            None
        """

        for (username, project_auth_id) in to_update:
            q = (
                sess.query(AccessPrivilege)
                .filter(AccessPrivilege.project.has(auth_id=project_auth_id))
                .join(AccessPrivilege.user)
                .filter(func.lower(User.username) == username)
                .all()
            )
            for access in q:
                access.privilege = user_project[username][project_auth_id]
                self.logger.info(
                    "update {} with {} access to {} in db".format(
                        username, access.privilege, project_auth_id
                    )
                )

    def _grant_from_db(self, sess, to_add, user_info, user_project, auth_provider_list):
        """
        Grant user access to projects in the auth database
        Args:
            sess: sqlalchemy session
            to_add: a set of (username, project.auth_id) to be granted
            user_project:
                a dictionary of {username: {project: {'read','write'}}
        Return:
            None
        """
        for (username, project_auth_id) in to_add:
            u = query_for_user(session=sess, username=username)

            auth_provider = auth_provider_list[0]
            if "dbgap_role" not in user_info[username]["tags"]:
                auth_provider = auth_provider_list[1]

            user_access = AccessPrivilege(
                user=u,
                project=self._projects[project_auth_id],
                privilege=list(user_project[username][project_auth_id]),
                auth_provider=auth_provider,
            )
            self.logger.info(
                "grant user {} to {} with access {}".format(
                    username, user_access.project, user_access.privilege
                )
            )
            sess.add(user_access)

    def _upsert_userinfo(self, sess, user_info):
        """
        update user info to database.

        Args:
            sess: sqlalchemy session
            user_info:
                a dict of {username: {display_name, phone_number, tags, admin}

        Return:
            None
        """

        for username in user_info:
            u = query_for_user(session=sess, username=username)

            if u is None:
                self.logger.info("create user {}".format(username))
                u = User(username=username)
                sess.add(u)

            if self.arborist_client:
                self.arborist_client.create_user({"name": username})

            u.email = user_info[username].get("email", "")
            u.display_name = user_info[username].get("display_name", "")
            u.phone_number = user_info[username].get("phone_number", "")
            u.is_admin = user_info[username].get("admin", False)

            # do not update if there is no tag
            if user_info[username]["tags"] == {}:
                continue

            # remove user db tags if they are not shown in new tags
            for tag in u.tags:
                if tag.key not in user_info[username]["tags"]:
                    u.tags.remove(tag)

            # sync
            for k, v in user_info[username]["tags"].items():
                found = False
                for tag in u.tags:
                    if tag.key == k:
                        found = True
                        tag.value = v
                # create new tag if not found
                if not found:
                    tag = Tag(key=k, value=v)
                    u.tags.append(tag)

    def _revoke_from_storage(self, to_delete, sess):
        """
        If a project have storage backend, revoke user's access to buckets in
        the storage backend.

        Args:
            to_delete: a set of (username, project.auth_id) to be revoked

        Return:
            None
        """
        for (username, project_auth_id) in to_delete:
            project = (
                sess.query(Project).filter(Project.auth_id == project_auth_id).first()
            )
            for sa in project.storage_access:
                if not getattr(self, "storage_manager"):
                    logging.error(
                        (
                            "CANNOT revoke {} access to {} in {} because there is NO "
                            "configured storage accesses at all. See configuration. "
                            "Continuing anyway..."
                        ).format(username, project_auth_id, sa.provider.name)
                    )
                    continue

                self.logger.info(
                    "revoke {} access to {} in {}".format(
                        username, project_auth_id, sa.provider.name
                    )
                )
                self.storage_manager.revoke_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project,
                    session=sess,
                )

    def _grant_from_storage(self, to_add, user_project, sess):
        """
        If a project have storage backend, grant user's access to buckets in
        the storage backend.

        Args:
            to_add: a set of (username, project.auth_id)  to be granted
            user_project: a dictionary like:

                    {username: {phsid: {'read-storage','write-storage'}}}

        Return:
            None
        """
        for (username, project_auth_id) in to_add:
            project = self._projects[project_auth_id]
            for sa in project.storage_access:
                access = list(user_project[username][project_auth_id])
                if not getattr(self, "storage_manager"):
                    logging.error(
                        (
                            "CANNOT grant {} access {} to {} in {} because there is NO "
                            "configured storage accesses at all. See configuration. "
                            "Continuing anyway..."
                        ).format(username, access, project_auth_id, sa.provider.name)
                    )
                    continue

                self.logger.info(
                    "grant {} access {} to {} in {}".format(
                        username, access, project_auth_id, sa.provider.name
                    )
                )
                self.storage_manager.grant_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project,
                    access=access,
                    session=sess,
                )

    def _init_projects(self, user_project, sess):
        """
        initialize projects
        """
        if self.project_mapping:
            for projects in list(self.project_mapping.values()):
                for p in projects:
                    self.logger.debug(
                        "creating Project with info from project_mapping: {}".format(p)
                    )
                    project = self._get_or_create(sess, Project, **p)
                    self._projects[p["auth_id"]] = project
        for _, projects in user_project.items():
            for auth_id in list(projects.keys()):
                project = sess.query(Project).filter(Project.auth_id == auth_id).first()
                if not project:
                    data = {"name": auth_id, "auth_id": auth_id}
                    try:
                        project = self._get_or_create(sess, Project, **data)
                    except IntegrityError as e:
                        sess.rollback()
                        self.logger.error(str(e))
                        raise Exception(
                            "Project {} already exists. Detail {}. Please contact your system administrator.".format(
                                auth_id, str(e)
                            )
                        )
                if auth_id not in self._projects:
                    self._projects[auth_id] = project

    @staticmethod
    def _get_or_create(sess, model, **kwargs):
        instance = sess.query(model).filter_by(**kwargs).first()
        if not instance:
            instance = model(**kwargs)
            sess.add(instance)
        return instance

    def _process_dbgap_files(self, dbgap_config, sess):
        """
        Args:
            dbgap_config : a dictionary containing information about a single
                           dbgap sftp server (from fence config)
            sess: database session

        Return:
            user_projects (dict)
            user_info (dict)
        """
        dbgap_file_list = []
        hostname = dbgap_config["info"]["host"]
        username = dbgap_config["info"]["username"]
        folderdir = os.path.join(str(self.folder), str(hostname), str(username))

        try:
            if os.path.exists(folderdir):
                dbgap_file_list = glob.glob(
                    os.path.join(folderdir, "*")
                )  # get lists of file from folder
            else:
                dbgap_file_list = self._download(dbgap_config)
        except Exception as e:
            self.logger.error(e)
            exit(1)
        self.logger.info("dbgap files: {}".format(dbgap_file_list))
        user_projects, user_info = self._get_user_permissions_from_csv_list(
            dbgap_file_list, encrypted=True, session=sess, dbgap_config=dbgap_config
        )

        user_projects = self.parse_projects(user_projects)
        return user_projects, user_info

    def _get_user_permissions_from_csv_list(
        self, file_list, encrypted, session, dbgap_config={}
    ):
        """
        Args:
            file_list: list of files (represented as strings)
            encrypted: boolean indicating whether those files are encrypted
            session: sqlalchemy session
            dbgap_config: a dictionary containing information about the dbGaP sftp server
                    (comes from fence config)

        Return:
            user_projects (dict)
            user_info (dict)
        """
        permissions = [{"read-storage", "read"} for _ in file_list]
        user_projects, user_info = self._parse_csv(
            dict(list(zip(file_list, permissions))),
            sess=session,
            dbgap_config=dbgap_config,
            encrypted=encrypted,
        )
        return user_projects, user_info

    def _merge_multiple_dbgap_sftp(self, dbgap_servers, sess):
        """
        Args:
            dbgap_servers : a list of dictionaries each containging config on
                           dbgap sftp server (comes from fence config)
            sess: database session

        Return:
            merged_user_projects (dict)
            merged_user_info (dict)
        """
        merged_user_projects = {}
        merged_user_info = {}
        for dbgap in dbgap_servers:
            user_projects, user_info = self._process_dbgap_files(dbgap, sess)
            # merge into merged_user_info
            # user_info overrides original info in merged_user_info
            self.sync_two_user_info_dict(user_info, merged_user_info)

            # merge all access info dicts into "merged_user_projects".
            # the access info is combined - if the user_projects access is
            # ["read"] and the merged_user_projects is ["read-storage"], the
            # resulting access is ["read", "read-storage"].
            self.sync_two_phsids_dict(user_projects, merged_user_projects)
        return merged_user_projects, merged_user_info

    def parse_projects(self, user_projects):
        """
        helper function for parsing projects
        """
        return {key.lower(): value for key, value in user_projects.items()}

    def sync(self):
        if self.session:
            self._sync(self.session)
        else:
            with self.driver.session as s:
                self._sync(s)

    def download(self):
        for dbgap_server in self.dbGaP:
            self._download(dbgap_server)

    def _download(self, dbgap_config):
        """
        Download files from dbgap server.
        """
        server = dbgap_config["info"]
        protocol = dbgap_config["protocol"]
        hostname = server["host"]
        username = server["username"]
        folderdir = os.path.join(str(self.folder), str(hostname), str(username))

        if not os.path.exists(folderdir):
            os.makedirs(folderdir)

        self.logger.info("Download from server")
        try:
            if protocol == "sftp":
                self._get_from_sftp_with_proxy(server, folderdir)
            else:
                self._get_from_ftp_with_proxy(server, folderdir)
            dbgap_files = glob.glob(os.path.join(folderdir, "*"))
            return dbgap_files
        except Exception as e:
            self.logger.error(e)
            exit(1)

    def _sync(self, sess):
        """
        Collect files from dbgap server(s), sync csv and yaml files to storage
        backend and fence DB
        """

        # get all dbgap files
        user_projects = {}
        user_info = {}
        if self.is_sync_from_dbgap_server:
            self.logger.debug(
                "Pulling telemetry files from {} dbgap sftp servers".format(
                    len(self.dbGaP)
                )
            )
            user_projects, user_info = self._merge_multiple_dbgap_sftp(self.dbGaP, sess)

        local_csv_file_list = []
        if self.sync_from_local_csv_dir:
            local_csv_file_list = glob.glob(
                os.path.join(self.sync_from_local_csv_dir, "*")
            )

        # if syncing from local csv dir dbgap configurations
        # come from the first dbgap instance in the fence config file
        user_projects_csv, user_info_csv = self._get_user_permissions_from_csv_list(
            local_csv_file_list,
            encrypted=False,
            session=sess,
            dbgap_config=self.dbGaP[0],
        )

        try:
            user_yaml = UserYAML.from_file(
                self.sync_from_local_yaml_file, encrypted=False, logger=self.logger
            )
        except (EnvironmentError, AssertionError) as e:
            self.logger.error(str(e))
            self.logger.error("aborting early")
            return

        # parse all projects
        user_projects_csv = self.parse_projects(user_projects_csv)
        user_projects = self.parse_projects(user_projects)
        user_yaml.projects = self.parse_projects(user_yaml.projects)

        # merge all user info dicts into "user_info".
        # the user info (such as email) in the user.yaml files
        # overrides the user info from the CSV files.
        self.sync_two_user_info_dict(user_info_csv, user_info)
        self.sync_two_user_info_dict(user_yaml.user_info, user_info)

        # merge all access info dicts into "user_projects".
        # the access info is combined - if the user.yaml access is
        # ["read"] and the CSV file access is ["read-storage"], the
        # resulting access is ["read", "read-storage"].
        self.sync_two_phsids_dict(user_projects_csv, user_projects)
        self.sync_two_phsids_dict(user_yaml.projects, user_projects)

        # Note: if there are multiple dbgap sftp servers configured
        # this parameter is always from the config for the first dbgap sftp server
        # not any additional ones
        if self.parse_consent_code:
            self._grant_all_consents_to_c999_users(
                user_projects, user_yaml.project_to_resource
            )

        # update the Fence DB
        if user_projects:
            self.logger.info("Sync to db and storage backend")
            self.sync_to_db_and_storage_backend(user_projects, user_info, sess)
            self.logger.info("Finish syncing to db and storage backend")
        else:
            self.logger.info("No users for syncing")

        # update the Arborist DB (resources, roles, policies, groups)
        if user_yaml.authz:
            if not self.arborist_client:
                raise EnvironmentError(
                    "yaml file contains authz section but sync is not configured with"
                    " arborist client--did you run sync with --arborist <arborist client> arg?"
                )
            self.logger.info("Synchronizing arborist...")
            success = self._update_arborist(sess, user_yaml)
            if success:
                self.logger.info("Finished synchronizing arborist")
            else:
                self.logger.error("Could not synchronize successfully")
                exit(1)
        else:
            self.logger.info("No `authz` section; skipping arborist sync")

        # update the Arborist DB (user access)
        if self.arborist_client:
            self.logger.info("Synchronizing arborist with authorization info...")
            success = self._update_authz_in_arborist(sess, user_projects, user_yaml)
            if success:
                self.logger.info(
                    "Finished synchronizing authorization info to arborist"
                )
            else:
                self.logger.error(
                    "Could not synchronize authorization info successfully to arborist"
                )
                exit(1)

    def _grant_all_consents_to_c999_users(
        self, user_projects, user_yaml_project_to_resources
    ):
        access_number_matcher = re.compile(config["DBGAP_ACCESSION_WITH_CONSENT_REGEX"])
        # combine dbgap/user.yaml projects into one big list (in case not all consents
        # are in either)
        all_projects = set(
            list(self._projects.keys()) + list(user_yaml_project_to_resources.keys())
        )

        self.logger.debug(f"all projects: {all_projects}")

        # construct a mapping from phsid (without consent) to all accessions with consent
        consent_mapping = {}
        for project in all_projects:
            phs_match = access_number_matcher.match(project)
            if phs_match:
                accession_number = phs_match.groupdict()

                # TODO: This is not handling the .v1.p1 at all
                consent_mapping.setdefault(accession_number["phsid"], set()).add(
                    ".".join([accession_number["phsid"], accession_number["consent"]])
                )

        self.logger.debug(f"consent mapping: {consent_mapping}")

        # go through existing access and find any c999's and make sure to give access to
        # all accessions with consent for that phsid
        for username, user_project_info in copy.deepcopy(user_projects).items():
            for project, _ in user_project_info.items():
                phs_match = access_number_matcher.match(project)
                if phs_match and phs_match.groupdict()["consent"] == "c999":
                    # give access to all consents
                    all_phsids_with_consent = consent_mapping.get(
                        phs_match.groupdict()["phsid"], []
                    )
                    self.logger.info(
                        f"user {username} has c999 consent group for: {project}. "
                        f"Granting access to all consents: {all_phsids_with_consent}"
                    )
                    # NOTE: Only giving read-storage at the moment (this is same
                    #       permission we give for other dbgap projects)
                    for phsid_with_consent in all_phsids_with_consent:
                        user_projects[username].update(
                            {phsid_with_consent: {"read-storage", "read"}}
                        )

    def _update_arborist(self, session, user_yaml):
        """
        Create roles, resources, policies, groups in arborist from the information in
        ``user_yaml``.

        The projects are sent to arborist as resources with paths like
        ``/projects/{project}``. Roles are created with just the original names
        for the privileges like ``"read-storage", "read"`` etc.

        Args:
            session (sqlalchemy.Session)
            user_yaml (UserYAML)

        Return:
            bool: success
        """
        healthy = self._is_arborist_healthy()
        if not healthy:
            return False

        # Set up the resource tree in arborist by combining provided resources with any
        # dbgap resources that were created before this.
        #
        # Why add dbgap resources if they've already been created?
        #   B/C Arborist's PUT update will override existing subresources. So if a dbgap
        #   resources was created under `/programs/phs000178` anything provided in
        #   user.yaml under `/programs` would completely wipe it out.
        resources = user_yaml.authz.get("resources", [])

        dbgap_resource_paths = []
        for path_list in self._dbgap_study_to_resources.values():
            dbgap_resource_paths.extend(path_list)

        self.logger.debug("user_yaml resources: {}".format(resources))
        self.logger.debug("dbgap resource paths: {}".format(dbgap_resource_paths))

        combined_resources = utils.combine_provided_and_dbgap_resources(
            resources, dbgap_resource_paths
        )

        for resource in combined_resources:
            try:
                self.logger.debug(
                    "attempting to update arborist resource: {}".format(resource)
                )
                self.arborist_client.update_resource("/", resource)
            except ArboristError as e:
                self.logger.error(e)
                # keep going; maybe just some conflicts from things existing already

        # update roles
        roles = user_yaml.authz.get("roles", [])
        for role in roles:
            try:
                response = self.arborist_client.create_role(role)
                if response:
                    self._created_roles.add(role["id"])
            except ArboristError as e:
                self.logger.error(e)
                # keep going; maybe just some conflicts from things existing already

        # update policies
        policies = user_yaml.authz.get("policies", [])
        for policy in policies:
            policy_id = policy.pop("id")
            try:
                self.logger.debug(
                    "Trying to upsert policy with id {}".format(policy_id)
                )
                response = self.arborist_client.update_policy(
                    policy_id, policy, create_if_not_exist=True
                )
            except ArboristError as e:
                self.logger.error(e)
                # keep going; maybe just some conflicts from things existing already
            else:
                if response:
                    self.logger.debug("Upserted policy with id {}".format(policy_id))
                    self._created_policies.add(policy_id)

        # update groups
        groups = user_yaml.authz.get("groups", [])

        # delete from arborist the groups that have been deleted
        # from the user.yaml
        arborist_groups = set(
            g["name"] for g in self.arborist_client.list_groups().get("groups", [])
        )
        useryaml_groups = set(g["name"] for g in groups)
        for deleted_group in arborist_groups.difference(useryaml_groups):
            # do not try to delete built in groups
            if deleted_group not in ["anonymous", "logged-in"]:
                self.arborist_client.delete_group(deleted_group)

        # create/update the groups defined in the user.yaml
        for group in groups:
            missing = {"name", "users", "policies"}.difference(set(group.keys()))
            if missing:
                name = group.get("name", "{MISSING NAME}")
                self.logger.error(
                    "group {} missing required field(s): {}".format(name, list(missing))
                )
                continue
            try:
                response = self.arborist_client.put_group(
                    group["name"],
                    # Arborist doesn't handle group descriptions yet
                    # description=group.get("description", ""),
                    users=group["users"],
                    policies=group["policies"],
                )
            except ArboristError as e:
                self.logger.info("couldn't put group: {}".format(str(e)))

        # Update policies for built-in (`anonymous` and `logged-in`) groups

        # First recreate these groups in order to clear out old, possibly deleted policies
        for builtin_group in ["anonymous", "logged-in"]:
            try:
                response = self.arborist_client.put_group(builtin_group)
            except ArboristError as e:
                self.logger.info("couldn't put group: {}".format(str(e)))

        # Now add back policies that are in the user.yaml
        for policy in user_yaml.authz.get("anonymous_policies", []):
            self.arborist_client.grant_group_policy("anonymous", policy)

        for policy in user_yaml.authz.get("all_users_policies", []):
            self.arborist_client.grant_group_policy("logged-in", policy)

        return True

    def _update_authz_in_arborist(self, session, user_projects, user_yaml=None):
        """
        Assign users policies in arborist from the information in
        ``user_projects`` and optionally a ``user_yaml``.

        The projects are sent to arborist as resources with paths like
        ``/projects/{project}``. Roles are created with just the original names
        for the privileges like ``"read-storage", "read"`` etc.

        Args:
            user_projects (dict)
            user_yaml (UserYAML) optional, if there are policies for users in a user.yaml

        Return:
            bool: success
        """
        healthy = self._is_arborist_healthy()
        if not healthy:
            return False

        self.logger.debug("user_projects: {}".format(user_projects))

        if user_yaml:
            self.logger.debug(
                "useryaml abac before lowering usernames: {}".format(
                    user_yaml.user_abac
                )
            )
            user_yaml.user_abac = {
                key.lower(): value for key, value in user_yaml.user_abac.items()
            }

            # update the project info with `projects` specified in user.yaml
            self.sync_two_phsids_dict(user_yaml.user_abac, user_projects)

        # get list of users from arborist to make sure users that are completely removed
        # from authorization sources get policies revoked
        arborist_user_projects = {}
        try:
            arborist_users = self.arborist_client.get(
                url=self.arborist_client._user_url
            ).json["users"]

            # construct user information, NOTE the lowering of the username. when adding/
            # removing access, the case in the Fence db is used. For combining access, it is
            # case-insensitive, so we lower
            arborist_user_projects = {
                user["name"].lower(): {} for user in arborist_users
            }
        except (ArboristError, KeyError) as error:
            # TODO usersync should probably exit with non-zero exit code at the end,
            #      but sync should continue from this point so there are no partial
            #      updates
            self.logger.warning(
                "Could not get list of users in Arborist, continuing anyway. "
                "WARNING: this sync will NOT remove access for users no longer in "
                f"authorization sources. Error: {error}"
            )

        # update the project info with users from arborist
        self.sync_two_phsids_dict(arborist_user_projects, user_projects)

        for username, user_project_info in user_projects.items():
            self.logger.info("processing user `{}`".format(username))
            user = query_for_user(session=session, username=username)
            if user:
                username = user.username

            self.arborist_client.create_user_if_not_exist(username)
            self.arborist_client.revoke_all_policies_for_user(username)

            for project, permissions in user_project_info.items():

                # check if this is a dbgap project, if it is, we need to get the right
                # resource path, otherwise just use given project as path
                paths = self._dbgap_study_to_resources.get(project, [project])

                if user_yaml:
                    try:
                        # check if project is in mapping and convert accordingly
                        paths = [user_yaml.project_to_resource[project]]
                    except KeyError:
                        pass

                self.logger.info(
                    "resource paths for project {}: {}".format(project, paths)
                )
                self.logger.debug("permissions: {}".format(permissions))

                for permission in permissions:
                    # "permission" in the dbgap sense, not the arborist sense
                    if permission not in self._created_roles:
                        try:
                            self.arborist_client.create_role(
                                arborist_role_for_permission(permission)
                            )
                        except ArboristError as e:
                            self.logger.info(
                                "not creating role for permission `{}`; {}".format(
                                    permission, str(e)
                                )
                            )
                        self._created_roles.add(permission)

                    for path in paths:
                        # If everything was created fine, grant a policy to
                        # this user which contains exactly just this resource,
                        # with this permission as a role.

                        # format project '/x/y/z' -> 'x.y.z'
                        # so the policy id will be something like 'x.y.z-create'
                        policy_id = _format_policy_id(path, permission)
                        if policy_id not in self._created_policies:
                            try:
                                self.arborist_client.update_policy(
                                    policy_id,
                                    {
                                        "description": "policy created by fence sync",
                                        "role_ids": [permission],
                                        "resource_paths": [path],
                                    },
                                    create_if_not_exist=True,
                                )
                            except ArboristError as e:
                                self.logger.info(
                                    "not creating policy in arborist; {}".format(str(e))
                                )
                            self._created_policies.add(policy_id)

                        self.arborist_client.grant_user_policy(username, policy_id)

            if user_yaml:
                for policy in user_yaml.policies.get(username, []):
                    self.arborist_client.grant_user_policy(username, policy)

        for client_name, client_details in user_yaml.clients.items():
            client_policies = client_details.get("policies", [])
            client = session.query(Client).filter_by(name=client_name).first()
            # update existing clients, do not create new ones
            if not client:
                self.logger.warning(
                    "client to update (`{}`) does not exist in fence: skipping".format(
                        client_name
                    )
                )
                continue
            try:
                self.arborist_client.update_client(client.client_id, client_policies)
            except ArboristError as e:
                self.logger.info(
                    "not granting policies {} to client `{}`; {}".format(
                        client_policies, client_name, str(e)
                    )
                )

        return True

    def _add_dbgap_study_to_arborist(self, dbgap_study, dbgap_config):
        """
        Return the arborist resource path after adding the specified dbgap study
        to arborist.

        Args:
            dbgap_study (str): study phs identifier
            dbgap_config (dict): dictionary of config for dbgap server

        Returns:
            str: arborist resource path for study
        """
        healthy = self._is_arborist_healthy()
        if not healthy:
            return False

        default_namespaces = dbgap_config.get("study_to_resource_namespaces", {}).get(
            "_default", ["/"]
        )
        namespaces = dbgap_config.get("study_to_resource_namespaces", {}).get(
            dbgap_study, default_namespaces
        )

        self.logger.debug(f"dbgap study namespaces: {namespaces}")

        arborist_resource_namespaces = [
            namespace.rstrip("/") + "/programs/" for namespace in namespaces
        ]

        try:
            for resource_namespace in arborist_resource_namespaces:
                response = self.arborist_client.update_resource(
                    resource_namespace,
                    {"name": dbgap_study, "description": "synced from dbGaP"},
                    create_parents=True,
                )
                self.logger.info(
                    "added arborist resource under parent path: {} for dbgap project {}.".format(
                        resource_namespace, dbgap_study
                    )
                )
                self.logger.debug("Arborist response: {}".format(response))
                if dbgap_study not in self._dbgap_study_to_resources:
                    self._dbgap_study_to_resources[dbgap_study] = []

                self._dbgap_study_to_resources[dbgap_study].append(
                    resource_namespace + dbgap_study
                )

            return arborist_resource_namespaces
        except ArboristError as e:
            self.logger.error(e)
            # keep going; maybe just some conflicts from things existing already

    def _is_arborist_healthy(self):
        if not self.arborist_client:
            self.logger.warn("no arborist client set; skipping arborist dbgap sync")
            return False
        if not self.arborist_client.healthy():
            # TODO (rudyardrichter, 2019-01-07): add backoff/retry here
            self.logger.error(
                "arborist service is unavailable; skipping main arborist dbgap sync"
            )
            return False
        return True
