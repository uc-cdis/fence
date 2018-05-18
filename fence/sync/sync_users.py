import os
from StringIO import StringIO
from collections import defaultdict
from contextlib import contextmanager
from csv import DictReader
import glob
import yaml
import re
import subprocess as sp
import tempfile
import shutil
import errno
import paramiko
from paramiko.proxy import ProxyCommand
from stat import S_ISDIR
from sqlalchemy import func

from cdispyutils.log import get_logger
from userdatamodel.driver import SQLAlchemyDriver

from fence.models import (
    Project,
    User,
    Tag,
    AccessPrivilege,
    AuthorizationProvider
)

from fence.resources.storage import StorageManager


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
            self, dbGaP, DB, project_mapping,
            storage_credentials=None, db_session=None,
            is_sync_from_dbgap_server=False,
            sync_from_local_csv_dir=None, sync_from_local_yaml_file=None):
        """
        Syncs ACL files from dbGap to auth database and storage backends
        Args:
            dbGaP: a dict containing creds to access dbgap sftp
            DB: database connection string
            project_mapping: a dict containing how dbgap ids map to projects
            storage_credentials: a dict containing creds for storage backends
            sync_from_dir: path to an alternative dir to sync from instead of
                           dbGaP
        """

        self.sync_from_local_csv_dir = sync_from_local_csv_dir
        self.sync_from_local_yaml_file = sync_from_local_yaml_file
        self.is_sync_from_dbgap_server = is_sync_from_dbgap_server
        if is_sync_from_dbgap_server:
            self.server = dbGaP['info']
            self.protocol = dbGaP['protocol']
            self.dbgap_key = dbGaP['decrypt_key']
        self.session = db_session
        self.driver = SQLAlchemyDriver(DB)
        self.project_mapping = project_mapping
        self._projects = dict()
        self.logger = get_logger('user_syncer')

        if storage_credentials:
            self.storage_manager = StorageManager(
                storage_credentials,
                logger=self.logger
            )

    def _match_pattern(self, filepath, encrypted=True):
        """
        Check if the filename match dbgap access control file patern
        Args:
            filepath (str): path to file
            encrypted (bool): whether the file is encrypted
        Returns:
            bool: whether the pattern matches
        """
        pattern = "authentication_file_phs(\d{6}).(csv|txt)"
        if encrypted:
            pattern += '.enc$'
        else:
            pattern += '$'
        return (re.match(pattern,
                         os.path.basename(filepath)))

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
            proxy = ProxyCommand('ssh -i ~/.ssh/id_rsa '
                                 '{}@{} nc {} {}'.format(
                                     self.server.get('proxy_user', ''),
                                     self.server.get('proxy', ''), self.server.get('host', ''), self.server.get('port', 22)))

        client = paramiko.SSHClient()
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
        sftp = client.open_sftp()

        download_dir(sftp, './', path)

        sftp.close()
        client.close()
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
        execstr = ("lftp -u {},{}  {} -e \"set ftp:proxy http://{}; mirror . {}; exit\"".format(self.server.get('username',
                                                                                                                ''), self.server.get('password', ''), self.server.get('host', ''), self.server.get('proxy', ''), path))
        os.system(execstr)

    @contextmanager
    def _read_file(self, filepath, encrypted=True):
        """
        Context manager for reading and optionally decrypting file
        it only decrypts files encrypted by unix 'crypt' tool
        which is used by dbGaP.
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
            p = sp.Popen(["crypt", self.dbgap_key],
                         stdin=open(filepath, 'r'),
                         stdout=sp.PIPE,
                         stderr=open(os.devnull, 'w')
                         )
            yield StringIO(p.communicate()[0])
        else:
            f = open(filepath, 'r')
            yield f
            f.close()

    def _parse_csv(self, file_dict, encrypted=True):
        """
        parse csv files to python dict
        Args:
            fild_dict: a dictionary with key(file path) and value(privileges)
            encrypted: whether those files are encrypted
        Return:
            user_project: a nested dict of
            {
                username: {
                    'project1': ['read-storage','write-storage'],
                    'project2': ['read-storage'],
                    }
            }
            user_info: a dict of
            {
                username: {
                    'email': 'email@mail.com',
                    'display_name': 'display name',
                    'phone_umber': '123-456-789',
                    'tags': {'dbgap_role': 'PI'}
                }
            }

        """
        user_projects = dict()
        user_info = dict()
        for filepath, privileges in file_dict.iteritems():
            if os.stat(filepath).st_size == 0:
                continue
            if self._match_pattern(filepath, encrypted=encrypted):
                try:
                    with self._read_file(filepath, encrypted=encrypted) as f:
                        csv = DictReader(f, quotechar='"',
                                         skipinitialspace=True)
                        for row in csv:
                            username = row.get('login', '')
                            if username == '':
                                continue

                            phsid_privileges = defaultdict(set)
                            dbgap_project = row.get('phsid', '').split('.')[0]

                            if not dbgap_project in self.project_mapping:
                                self.logger.info(
                                    "{} is not in project mapping".format(dbgap_project))
                                continue

                            for element_dict in self.project_mapping[dbgap_project]:
                                try:
                                    phsid_privileges = {
                                        element_dict['auth_id']: privileges}
                                    if username in user_projects:
                                        user_projects[username].update(
                                            phsid_privileges)
                                    else:
                                        user_projects[username] = phsid_privileges
                                except ValueError as e:
                                    self.logger.info(e)

                            display_name = row.get('user name', '')
                            user_info[username] = {
                                'email': row.get('email', ''),
                                'display_name': display_name,
                                'phone_number': row.get('phone', ''),
                                'tags': {'dbgap_role': row.get('role', '')}
                            }
                except Exception as e:
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
                    'project1': ['read-storage','write-storage'],
                    'project2': ['read-storage'],
                    }
            }
            user_info: a dict of 
            {
                username: {
                    'email': email,
                    'display_name': display_name,
                    'phone_number': phonenum,
                    'tags': {'k1':'v1', 'k2': 'v2'}
                }
            }
        """
        user_project = dict()
        user_info = dict()

        if filepath is None:
            return user_project, user_info

        try:
            with self._read_file(filepath, encrypted=encrypted) as stream:
                data = yaml.safe_load(stream)
                users = data.get('users', {})
                for username, details in users.iteritems():
                    privileges = defaultdict(set)

                    try:
                        for project in details.get('projects', {}):
                            privileges[project['auth_id']
                                       ] = project['privilege']

                    except KeyError as e:
                        self.logger.info(e)
                        continue

                    user_info[username] = {
                        'email': details.get('email', username),
                        'display_name': details.get('display_name', ''),
                        'phone_number': details.get('phone_number', ''),
                        'tags': details.get('tags', {}),
                    }

                    if not username in user_project:
                        user_project[username] = (privileges)
                    else:
                        user_project[username].add(privileges)
        except IOError as e:
            self.logger.info(e)

        return user_project, user_info

    @classmethod
    def sync_two_user_info_dict(self, user_info1, user_info2):
        """
        merge user_info1 into user_info2
        Args:
            user_info1, user_info2: nested dicts of {username: {'email': 'abc@email.com'}}
        Returns:
            None
        """
        for user, info1 in user_info1.iteritems():
            info2 = user_info2.get(user)
            if not info2:
                user_info2.update({user: info1})
                continue
            user_info2[user] = info1

    @classmethod
    def sync_two_phsids_dict(self, phsids1, phsids2):
        """
        merge pshid1 into phsids2
        Args:
            phsids1, phsids2: nested dicts of
            {
                username: {
                    phsid1: ['read-storage','write-storage'],
                    phsid2: ['read-storage'],
                    }
            }
        Returns:
            None
        Explaination:
            consider merging projects of the same user: {user1: {phsid1: privillege1}} and {user1: {phsid2: privillege2}}:
                case 1: phsid1 != phsid2. Output: {user1: {phsid1: privillege1,
                                                           phsid2: privillege2}}
                case2: phsid1 == phsid2 and privillege1! = privillege2. Output {user1: {phsid1: uion(privillege1, privillege2)}}
            For the other cases, just simple addition
        """
        #phsids = copy.deepcopy(phsids2)
        for user, projects1 in phsids1.iteritems():
            projects2 = phsids2.get(user)
            if not projects2:
                phsids2.update({user: projects1})
                continue
            for phsid1, privilege1 in projects1.iteritems():
                if phsid1 in phsids2[user]:
                    phsids2[user][phsid1].update(privilege1)
                else:
                    phsids2[user][phsid1] = privilege1

    def sync_to_db_and_storage_backend(self, user_project, user_info, sess):
        """
        sync user access control to database and storage backend
        Args:
            user_project(dict): a dictionary of
            {
                username: {
                    'project1': ['read-storage','write-storage'],
                    'project2': ['read-storage']
                }
            }
            user_info(dict): a dictionary of {username: user_info{}}
            use_mapping(bool)
            sess: a sqlalchemy session
        Return:
            None
        """
        self._init_projects(user_project, sess)

        auth_provider_list = [self._get_or_create(
            sess, AuthorizationProvider, name='dbGaP'),
            self._get_or_create(
            sess, AuthorizationProvider, name='fence')]

        cur_db_user_project_list = {
            (ua.user.username, ua.project.auth_id) for
            ua in sess.query(AccessPrivilege).all()}

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
        self._grant_from_storage(to_add, user_project)
        self._grant_from_db(sess, to_add, user_info,
                            user_project, auth_provider_list)

        # re-grant
        self._grant_from_storage(to_update, user_project)
        self._update_from_db(sess, to_update, user_project)

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

            q = (sess.query(AccessPrivilege)
                 .filter(AccessPrivilege.user.has(username=username))
                 .filter(AccessPrivilege.project.has(auth_id=project_auth_id))
                 .all())
            for access in q:
                self.logger.info(
                    "revoke {} access to {} in db"
                    .format(username, project_auth_id))
                sess.delete(access)
        sess.commit()

    def _update_from_db(self, sess, to_update, user_project):
        """
        Update user access to projects in the auth database
        Args:
            sess: sqlalchemy session
            to_update: a set of (username, project.auth_id) to be updated from db
        Return:
            None
        """

        for (username, project_auth_id) in to_update:
            q = (sess.query(AccessPrivilege)
                 .filter(AccessPrivilege.user.has(username=username))
                 .filter(AccessPrivilege.project.has(auth_id=project_auth_id))
                 .all())
            for access in q:
                self.logger.info(
                    "update {} access to {} in db"
                    .format(username, project_auth_id))
                access.privilege = user_project[username][project_auth_id]

        sess.commit()

    def _grant_from_db(
            self, sess, to_add, user_info,
            user_project, auth_provider_list):
        """
        Grant user access to projects in the auth database
        Args:
            sess: sqlalchemy session
            to_add: a set of (username, project.auth_id) to be granted
            user_project: a dictionary of {username: {project: ['read','write']}
        Return:
            None
        """
        for (username, project_auth_id) in to_add:
            self.logger.info('update user info {}'.format(username))
            u = sess.query(User).filter(func.lower(User.username) == username.lower()).first()
            auth_provider = auth_provider_list[0]
            if 'dbgap_role' not in user_info[username]['tags']:
                auth_provider = auth_provider_list[1]

            user_access = AccessPrivilege(
                user=u,
                project=self._projects[project_auth_id],
                privilege=list(
                    user_project[username][project_auth_id]),
                auth_provider=auth_provider)
            sess.add(user_access)

        sess.commit()

    def _upsert_userinfo(self, sess, user_info):
        """
        update user info to database.
        Args:
            sess: sqlalchemy session
            user_info: a dict of {username: {display_name, phone_number, tags: {k:v}}}
        Return:
            None
        """

        for username in user_info:
            u = sess.query(User).filter(func.lower(User.username) == username.lower()).first()

            if u is None:
                self.logger.info('create user {}'.format(username))
                u = User(username=username)
                sess.add(u)

            u.email = user_info[username].get('email', '')
            u.display_name = user_info[username].get('display_name', '')
            u.phone_number = user_info[username].get('phone_number', '')

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
        If a project have storage backend,
        revoke user's access to buckets in the storage backend
        Args:
            to_delete: a set of (username, project.auth_id) to be revoked
        Return:
            None
        """
        for (username, project_auth_id) in to_delete:
            project = sess.query(Project).filter(
                Project.auth_id == project_auth_id).first()
            for sa in project.storage_access:

                self.logger.info(
                    'revoke {} access to {} in {}'
                    .format(username, project, sa.provider.name))

                self.storage_manager.revoke_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project
                )
        sess.commit()

    def _grant_from_storage(self, to_add, user_project):
        """
        If a project have storage backend,
        grant user's access to buckets in the storage backend
        Args:
            to_add: a set of (username, project.auth_id)  to be granted
            user_project: a dictionary of {username: {phsid: ['read-storage','write-storage']}
        Return:
            None
        """

        for (username, project_auth_id) in to_add:
            project = self._projects[project_auth_id]
            for sa in project.storage_access:
                self.logger.info(
                    'grant {} access to {} in {}'
                    .format(username, project, sa.provider.name))

                access = list(user_project[username][project_auth_id])
                self.storage_manager.grant_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project,
                    access=access
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
                project = sess.query(Project).filter(
                    Project.auth_id == project_name).first()
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
        Collect files from dbgap server
        sync csv and yaml files to storage backend and fence DB

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

        user_projects1, user_info1 = self._parse_csv(
            dict(zip(dbgap_file_list, [
                 ['read-storage']]*len(dbgap_file_list))),
            encrypted=True)

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

        user_projects2, user_info2 = self._parse_csv(
            dict(zip(local_csv_file_list, [
                 ['read-storage']]*len(local_csv_file_list))),
            encrypted=False)

        user_projects3, user_info3 = self._parse_yaml(
            self.sync_from_local_yaml_file, encrypted=False)

        self.sync_two_phsids_dict(user_projects2, user_projects1)
        self.sync_two_user_info_dict(user_info2, user_info1)

        # privilleges in yaml files overide ones in csv files
        self.sync_two_phsids_dict(user_projects3, user_projects1)
        self.sync_two_user_info_dict(user_info3, user_info1)

        if len(user_projects1) > 0:
            self.logger.info('Sync to db and storage backend')
            self.sync_to_db_and_storage_backend(
                user_projects1, user_info1, sess)
            self.logger.info('Finish syncing to db and storage backend')
        else:
            self.logger.info('No users for syncing!!!')


if __name__ == '__main__':
    DB = 'postgresql://test:test@localhost:5432/fence_test'
    driver = SQLAlchemyDriver(DB)
    with driver.session as sess:
        user = sess.query(User).filter(User.id == 17).first()
        import pdb
        pdb.set_trace()
        dir(user)
        print(user)
        tags = user.tags
        print(type(tags))
