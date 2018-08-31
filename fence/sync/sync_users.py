from contextlib import contextmanager
from csv import DictReader
import errno
import glob
import os
import re
from StringIO import StringIO
import subprocess as sp
import tempfile
import shutil
from stat import S_ISDIR
import yaml

from cdispyutils.log import get_logger
import paramiko
from paramiko.proxy import ProxyCommand
from sqlalchemy import func
from userdatamodel.driver import SQLAlchemyDriver

from fence.models import (
    AccessPrivilege,
    AuthorizationProvider,
    Policy,
    Project,
    Tag,
    User,
)
from fence.rbac.client import ArboristClient, ArboristError
from fence.resources.storage import StorageManager


def _format_policy_id(path, privilege):
    resource = '.'.join(name for name in path.split('/') if name)
    return '{}-{}'.format(resource, privilege)


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
        remote_path = remote_dir + '/' + item.filename
        local_path = os.path.join(local_dir, item.filename)
        if S_ISDIR(item.st_mode):
            download_dir(sftp, remote_path, local_path)
        else:
            sftp.get(remote_path, local_path)


class UserSyncer(object):

    def __init__(
            self, dbGaP, DB, project_mapping, storage_credentials=None,
            db_session=None, is_sync_from_dbgap_server=False,
            sync_from_local_csv_dir=None, sync_from_local_yaml_file=None,
            arborist=None):
        """
        Syncs ACL files from dbGap to auth database and storage backends
        Args:
            dbGaP: a dict containing creds to access dbgap sftp
            DB: database connection string
            project_mapping: a dict containing how dbgap ids map to projects
            storage_credentials: a dict containing creds for storage backends
            sync_from_dir: path to an alternative dir to sync from instead of
                           dbGaP
            arborist:
                base URL for arborist service if the syncer should also create
                resources in arborist
        """
        self.sync_from_local_csv_dir = sync_from_local_csv_dir
        self.sync_from_local_yaml_file = sync_from_local_yaml_file
        self.is_sync_from_dbgap_server = is_sync_from_dbgap_server
        if is_sync_from_dbgap_server:
            self.server = dbGaP['info']
            self.protocol = dbGaP['protocol']
            self.dbgap_key = dbGaP['decrypt_key']
        self.parse_consent_code = dbGaP.get('parse_consent_code', True)
        self.session = db_session
        self.driver = SQLAlchemyDriver(DB)
        self.project_mapping = project_mapping or {}
        self._projects = dict()
        self.logger = get_logger('user_syncer')

        self.arborist_client = None
        if arborist:
            self.arborist_client = ArboristClient(
                arborist_base_url=arborist,
                logger=self.logger,
            )

        if storage_credentials:
            self.storage_manager = StorageManager(
                storage_credentials,
                logger=self.logger
            )

    @staticmethod
    def _match_pattern(filepath, encrypted=True):
        """
        Check if the filename match dbgap access control file patern

        Args:
            filepath (str): path to file
            encrypted (bool): whether the file is encrypted

        Returns:
            bool: whether the pattern matches
        """
        pattern = r"authentication_file_phs(\d{6}).(csv|txt)"
        if encrypted:
            pattern += '.enc'
        pattern += '$'
        return re.match(pattern, os.path.basename(filepath))

    def _get_from_sftp_with_proxy(self, path):
        """
        Download all data from sftp sever to a local dir

        Args:
            path (str): path to local directory

        Returns:
            None
        """
        proxy = None
        if self.server.get('proxy', '') != '':
            proxy = ProxyCommand(
                'ssh -i ~/.ssh/id_rsa {user}@{proxy} nc {host} {port}'
                .format(
                    user=self.server.get('proxy_user', ''),
                    proxy=self.server.get('proxy', ''),
                    host=self.server.get('host', ''),
                    port=self.server.get('port', 22),
                )
            )

        with paramiko.SSHClient() as client:
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            parameters = {
                "hostname": self.server.get('host', ''),
                "username": self.server.get('username', ''),
                "password": self.server.get('password', ''),
                "port": self.server.get('port', 22),
            }
            if proxy:
                parameters['sock'] = proxy
            client.connect(**parameters)
            with client.open_sftp() as sftp:
                download_dir(sftp, './', path)

        if proxy:
            proxy.close()

    def _get_from_ftp_with_proxy(self, path):
        """
        Download data from ftp sever to alocal dir

        Args:
            path(str): path to local files

        Returns:
            None
        """
        execstr = (
            "lftp -u {},{}  {} -e \"set ftp:proxy http://{}; mirror . {}; exit\""
            .format(
                self.server.get('username', ''),
                self.server.get('password', ''),
                self.server.get('host', ''),
                self.server.get('proxy', ''),
                path,
            )
        )
        os.system(execstr)

    @contextmanager
    def _read_file(self, filepath, encrypted=True):
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
            has_crypt = sp.call(['which', 'crypt'])
            if has_crypt != 0:
                self.logger.error(
                    'Need to install crypt to decrypt files from dbgap')
                exit(1)
            p = sp.Popen(
                ["crypt", self.dbgap_key],
                stdin=open(filepath, 'r'),
                stdout=sp.PIPE,
                stderr=open(os.devnull, 'w'),
            )
            yield StringIO(p.communicate()[0])
        else:
            f = open(filepath, 'r')
            yield f
            f.close()

    def _parse_csv(self, file_dict, sess, encrypted=True):
        """
        parse csv files to python dict

        Args:
            fild_dict: a dictionary with key(file path) and value(privileges)
            encrypted: whether those files are encrypted
            sess: sqlalchemy session

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
                        'phone_umber': '123-456-789',
                        'tags': {'dbgap_role': 'PI'}
                    }
                },
            )

        """
        user_projects = dict()
        user_info = dict()
        for filepath, privileges in file_dict.iteritems():
            self.logger.info('Reading file {}'.format(filepath))
            if os.stat(filepath).st_size == 0:
                continue
            if not self._match_pattern(filepath, encrypted=encrypted):
                continue

            with self._read_file(filepath, encrypted=encrypted) as f:
                csv = DictReader(f, quotechar='"', skipinitialspace=True)
                for row in csv:
                    username = row.get('login', '')
                    if username == '':
                        continue

                    phsid_privileges = {}
                    phsid = row.get('phsid', '').split('.')
                    dbgap_project = phsid[0]
                    if len(phsid) > 1 and self.parse_consent_code:
                        consent_code = phsid[-1]
                        if consent_code != 'c999':
                            dbgap_project += '.' + consent_code

                    display_name = row.get('user name', '')
                    user_info[username] = {
                        'email': row.get('email', ''),
                        'display_name': display_name,
                        'phone_number': row.get('phone', ''),
                        'tags': {'dbgap_role': row.get('role', '')}
                    }

                    if dbgap_project not in self.project_mapping:
                        if dbgap_project not in self._projects:
                            project = self._get_or_create(
                                sess, Project, auth_id=dbgap_project)
                            if project.name is None:
                                project.name = dbgap_project
                            self._projects[dbgap_project] = project
                        phsid_privileges = {dbgap_project: set(privileges)}
                        if username in user_projects:
                            user_projects[username].update(phsid_privileges)
                        else:
                            user_projects[username] = phsid_privileges

                    for element_dict in self.project_mapping.get(
                            dbgap_project, []):
                        try:
                            phsid_privileges = {
                                element_dict['auth_id']: set(privileges),
                            }
                            if username not in user_projects:
                                user_projects[username] = {}
                            user_projects[username].update(
                                phsid_privileges
                            )
                        except ValueError as e:
                            self.logger.info(e)
        return user_projects, user_info

    def _parse_yaml(self, filepath, encrypted=True):
        """
        parse yaml files to python nested dictionary
        Args:
            filepath: yaml file
            encrypted: whether those files are encrypted
        Returns:
            user_project: a nested dict of
            {
                username: {
                    'project1': {'read-storage','write-storage'},
                    'project2': {'read-storage'},
                    }
            }
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
        """
        user_project = dict()
        user_info = dict()

        with self._read_file(filepath, encrypted=encrypted) as stream:
            data = yaml.safe_load(stream)

        users = data.get('users', {})
        for username, details in users.iteritems():
            # users should occur only once each; skip if already processed
            if username in user_project:
                self.logger.error(
                    'user `{}` occurs multiple times'
                    .format(username)
                )
                raise EnvironmentError('invalid yaml file')

            privileges = {}

            try:
                for project in details.get('projects', {}):
                    privileges[project['auth_id']] = set(project['privilege'])
            except KeyError as e:
                self.logger.error('project missing field: {}'.format(e))
                continue

            user_info[username] = {
                'email': details.get('email', username),
                'display_name': details.get('display_name', ''),
                'phone_number': details.get('phone_number', ''),
                'tags': details.get('tags', {}),
                'admin': details.get('admin', False),
            }
            user_project[username] = privileges

        return user_project, user_info

    def _parse_resources_from_yaml(self, filepath, encrypted=True):
        """
        Args:
            filepath (str): path to user yaml file

        Return:
            Tuple[
                Mapping[str, Mapping[str, Set[str]]],
                Mapping[str, Union[str, Mapping[...]]],
            ]:
                the type is complicated---there's two parts:
                    - first the per-resource-path permissions for every user:
                        username -> (mapping: resource path -> set(permission))
                    - second the entire resource tree that gets handed to
                      arborist, which is a recursive type
        """
        data = dict()
        with self._read_file(filepath, encrypted=encrypted) as f:
            data = yaml.safe_load(f)

        users = data.get('users', {})
        result = dict()
        # resources should be the resource tree to construct in arborist
        resources = data.get('resources')

        for username, user_info in users.iteritems():
            # users should occur only once each; skip if already processed
            if username in result:
                msg = (
                    'invalid yaml file: user `{}` occurs multiple times'
                    .format(username)
                )
                self.logger.error(msg)
                raise EnvironmentError(msg)
            resource_permissions = dict()
            for project in user_info.get('projects', {}):
                try:
                    resource_permissions[project['resource']] = set(
                        project['privilege']
                    )
                except KeyError as e:
                    self.logger.error(
                        'user YAML file: project for user {} missing field {}'
                        .format(username, e)
                    )
            result[username] = resource_permissions

        return result, resources

    @staticmethod
    def sync_two_user_info_dict(user_info1, user_info2):
        """
        Merge user_info1 into user_info2, which are both nested dicts like:

            {username: {'email': 'abc@email.com'}}

        Args:
            user_info1 (dict)
            user_info2 (dict)

        Returns:
            None
        """
        user_info2.update(user_info1)

    @staticmethod
    def sync_two_phsids_dict(phsids1, phsids2):
        """
        Merge pshid1 into phsids2

        Args:
            phsids1, phsids2: nested dicts mapping phsids to sets of permissions

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
        for user, projects1 in phsids1.iteritems():
            if not phsids2.get(user):
                phsids2[user] = projects1
            else:
                for phsid1, privilege1 in projects1.iteritems():
                    if phsid1 not in phsids2[user]:
                        phsids2[user][phsid1] = set()
                    phsids2[user][phsid1].update(privilege1)

    def sync_to_db_and_storage_backend(self, user_project, user_info, sess):
        """
        sync user access control to database and storage backend

        Args:
            user_project(dict): a dictionary of
            {
                username: {
                    'project1': {'read-storage','write-storage'},
                    'project2': {'read-storage'}
                }
            }
            user_info(dict): a dictionary of {username: user_info{}}
            use_mapping(bool)
            sess: a sqlalchemy session

        Return:
            None
        """
        self._init_projects(user_project, sess)

        auth_provider_list = [
            self._get_or_create(sess, AuthorizationProvider, name='dbGaP'),
            self._get_or_create(sess, AuthorizationProvider, name='fence'),
        ]

        cur_db_user_project_list = {
            (ua.user.username, ua.project.auth_id)
            for ua in sess.query(AccessPrivilege).all()
        }

        syncing_user_project_list = set()
        for username, projects in user_project.iteritems():
            for project, _ in projects.iteritems():
                syncing_user_project_list.add((username, project))

        to_delete = set.difference(
            cur_db_user_project_list, syncing_user_project_list)
        to_add = set.difference(
            syncing_user_project_list, cur_db_user_project_list)
        to_update = set.intersection(
            cur_db_user_project_list, syncing_user_project_list)

        self._upsert_userinfo(sess, user_info)
        self._revoke_from_storage(to_delete, sess)
        self._revoke_from_db(sess, to_delete)
        self._grant_from_storage(to_add, user_project, sess)
        self._grant_from_db(
            sess, to_add, user_info, user_project, auth_provider_list
        )

        # re-grant
        self._grant_from_storage(to_update, user_project, sess)
        self._update_from_db(sess, to_update, user_project)

        self._validate_and_update_user_admin(sess, user_info)

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
                sess
                .query(AccessPrivilege)
                .filter(AccessPrivilege.user.has(username=username))
                .filter(AccessPrivilege.project.has(auth_id=project_auth_id))
                .all()
            )
            for access in q:
                self.logger.info(
                    "revoke {} access to {} in db"
                    .format(username, project_auth_id)
                )
                sess.delete(access)

        sess.commit()

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
        for admin_user in (
                sess
                .query(User)
                .filter_by(is_admin=True)
                .all()
                ):
            if admin_user.username not in user_info:
                admin_user.is_admin = False
                sess.add(admin_user)
                self.logger.info(
                    "remove admin access from {} in db"
                    .format(admin_user.username)
                )
        sess.commit()

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
                sess
                .query(AccessPrivilege)
                .filter(AccessPrivilege.user.has(username=username))
                .filter(AccessPrivilege.project.has(auth_id=project_auth_id))
                .all()
            )
            for access in q:
                access.privilege = user_project[username][project_auth_id]
                self.logger.info(
                    "update {} with {} access to {} in db"
                    .format(username, access.privilege, project_auth_id)
                )

        sess.commit()

    def _grant_from_db(
            self, sess, to_add, user_info, user_project, auth_provider_list):
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
            u = (
                sess
                .query(User)
                .filter(func.lower(User.username) == username.lower())
                .first()
            )
            auth_provider = auth_provider_list[0]
            if 'dbgap_role' not in user_info[username]['tags']:
                auth_provider = auth_provider_list[1]

            user_access = AccessPrivilege(
                user=u,
                project=self._projects[project_auth_id],
                privilege=list(
                    user_project[username][project_auth_id]),
                auth_provider=auth_provider)
            self.logger.info(
                'grant user {} to {} with access {}'
                .format(username, user_access.project, user_access.privilege)
            )
            sess.add(user_access)

        sess.commit()

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
            u = (
                sess
                .query(User)
                .filter(func.lower(User.username) == username.lower())
                .first()
            )

            if u is None:
                self.logger.info('create user {}'.format(username))
                u = User(username=username)
                sess.add(u)

            u.email = user_info[username].get('email', '')
            u.display_name = user_info[username].get('display_name', '')
            u.phone_number = user_info[username].get('phone_number', '')
            u.is_admin = user_info[username].get('admin', False)

            # do not update if there is no tag
            if user_info[username]['tags'] == {}:
                continue

            # remove user db tags if they are not shown in new tags
            for tag in u.tags:
                if tag.key not in user_info[username]['tags']:
                    u.tags.remove(tag)

            # sync
            for k, v in user_info[username]['tags'].iteritems():
                found = False
                for tag in u.tags:
                    if tag.key == k:
                        found = True
                        tag.value = v
                # create new tag if not found
                if not found:
                    tag = Tag(key=k, value=v)
                    u.tags.append(tag)

        sess.commit()

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
                sess
                .query(Project)
                .filter(Project.auth_id == project_auth_id)
                .first()
            )
            for sa in project.storage_access:
                self.logger.info(
                    'revoke {} access to {} in {}'
                    .format(username, project_auth_id, sa.provider.name)
                )
                self.storage_manager.revoke_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project,
                    session=sess
                )
        sess.commit()

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
                self.logger.info(
                    'grant {} access {} to {} in {}'
                    .format(
                        username, access, project_auth_id, sa.provider.name
                    )
                )
                self.storage_manager.grant_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project,
                    access=access,
                    session=sess
                )

    def _init_projects(self, user_project, sess):
        """
        initialize projects
        """
        if self.project_mapping:
            for projects in self.project_mapping.values():
                for p in projects:
                    project = self._get_or_create(sess, Project, **p)
                    self._projects[p['auth_id']] = project
        for _, projects in user_project.iteritems():
            for project_name in projects.keys():
                project = (
                    sess
                    .query(Project)
                    .filter(Project.auth_id == project_name)
                    .first()
                )
                if not project:
                    data = {'name': project_name, 'auth_id': project_name}
                    project = self._get_or_create(sess, Project, **data)
                if project_name not in self._projects:
                    self._projects[project_name] = project

    @classmethod
    def _get_or_create(self, sess, model, **kwargs):
        instance = sess.query(model).filter_by(**kwargs).first()
        if not instance:
            instance = model(**kwargs)
            sess.add(instance)
        return instance

    def sync(self):
        if self.session:
            self._sync(self.session)
        else:
            with self.driver.session as s:
                self._sync(s)

    def _sync(self, sess):
        """
        Collect files from dbgap server, sync csv and yaml files to storage
        backend and fence DB
        """
        dbgap_file_list = []
        tmpdir = tempfile.mkdtemp()
        if self.is_sync_from_dbgap_server:
            self.logger.info('Download from server')
            try:
                if self.protocol == 'sftp':
                    self._get_from_sftp_with_proxy(tmpdir)
                else:
                    self._get_from_ftp_with_proxy(tmpdir)
                dbgap_file_list = glob.glob(os.path.join(tmpdir, '*'))
            except Exception as e:
                self.logger.info(e)
        permissions = [{'read-storage'} for _ in dbgap_file_list]
        user_projects, user_info = self._parse_csv(
            dict(zip(dbgap_file_list, permissions)),
            encrypted=True,
            sess=sess,
        )
        try:
            shutil.rmtree(tmpdir)
        except OSError as e:
            self.logger.info(e)
            if e.errno != errno.ENOENT:
                raise

        local_csv_file_list = []
        if self.sync_from_local_csv_dir:
            local_csv_file_list = glob.glob(
                os.path.join(self.sync_from_local_csv_dir, '*'))

        permissions = [{'read-storage'} for _ in local_csv_file_list]
        user_projects_csv, user_info_csv = self._parse_csv(
            dict(zip(local_csv_file_list, permissions)),
            encrypted=False,
            sess=sess,
        )

        try:
            user_projects_yaml, user_info_yaml = self._parse_yaml(
                self.sync_from_local_yaml_file, encrypted=False
            )
            user_arborist_info, resources = self._parse_resources_from_yaml(
                self.sync_from_local_yaml_file, encrypted=False
            )
        except EnvironmentError as e:
            self.logger.error(str(e))
            self.logger.error('aborting early')
            return

        self.sync_two_phsids_dict(user_projects_csv, user_projects)
        self.sync_two_user_info_dict(user_info_csv, user_info)

        # privilleges in yaml files overide ones in csv files
        self.sync_two_phsids_dict(user_projects_yaml, user_projects)
        self.sync_two_user_info_dict(user_info_yaml, user_info)

        if user_projects:
            self.logger.info('Sync to db and storage backend')
            self.sync_to_db_and_storage_backend(user_projects, user_info, sess)
            self.logger.info('Finish syncing to db and storage backend')
        else:
            self.logger.info('No users for syncing')

        if resources:
            self.logger.info('Synchronizing arborist')
            success = self._update_arborist(sess, resources, user_arborist_info)
            if success:
                self.logger.info('Finished synchronizing arborist')
            else:
                self.logger.info('Could not synchronize successfully')
        else:
            self.logger.info('No resources specified; skipping arborist sync')

    def _update_arborist(self, session, resources, user_projects):
        """
        Create roles and resources in arborist from the information in
        ``user_projects``.

        The projects are sent to arborist as resources with paths like
        ``/projects/{project}``. Roles are created with just the original names
        for the privileges like ``"read-storage"`` etc.

        Args:
            user_projects (dict)
            session (sqlalchemy.Session)

        Return:
            bool: success
        """
        if not self.arborist_client:
            self.logger.warn('no arborist client set; skipping arborist sync')
            return False
        if not self.arborist_client.healthy():
            self.logger.error(
                'arborist service is unavailable; skipping arborist sync'
            )
            return False

        # Set up the resource tree in arborist
        if resources:
            try:
                self.arborist_client.create_resource('/', resources)
            except ArboristError as e:
                self.logger.error(e)
                return False

        created_roles = set()
        created_policies = set()

        for username, user_resources in user_projects.iteritems():
            self.logger.info('processing user `{}`'.format(username))
            user = (
                session
                .query(User)
                .filter(func.lower(User.username) == username.lower())
                .first()
            )
            # reset user policies; update to exactly what's in the yaml file
            user.policies = []
            for path, permissions in user_resources.iteritems():
                for permission in permissions:
                    # "permission" in the dbgap sense, not the arborist sense
                    if permission not in created_roles:
                        try:
                            self.arborist_client.create_role({
                                'id': permission,
                                'permissions': [
                                    {
                                        'id': permission,
                                        'action': {
                                            'service': '',
                                            'method': permission,
                                        },
                                    }
                                ],
                            })
                        except ArboristError:
                            continue
                        created_roles.add(permission)

                    # If everything was created fine, grant a policy to
                    # this user which contains exactly just this resource,
                    # with this permission as a role.

                    # format project '/x/y/z' -> 'x.y.z'
                    # so the policy id will be something like 'x.y.z-create'
                    policy_id = _format_policy_id(path, permission)
                    if policy_id not in created_policies:
                        try:
                            self.arborist_client.create_policy({
                                'id': policy_id,
                                'description': 'policy created by fence sync',
                                'role_ids': [permission],
                                'resource_paths': [path],
                            })
                        except ArboristError:
                            continue
                        created_policies.add(policy_id)
                    policy = (
                        session
                        .query(Policy)
                        .filter_by(id=policy_id)
                        .first()
                    )
                    if not policy:
                        policy = Policy(id=policy_id)
                        self.logger.info(
                            'created policy `{}`'.format(policy_id)
                        )
                    user.policies.append(policy)
                    self.logger.info(
                        'granted policy `{}` to user `{}`'
                        .format(policy_id, user.username)
                    )

        session.commit()
        return True
