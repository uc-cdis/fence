import os
from StringIO import StringIO
from collections import defaultdict
from contextlib import contextmanager
from csv import DictReader
import glob
import pysftp
import yaml
import re
import subprocess as sp
#import temps
import tempfile
import shutil
import errno
from cdispyutils.log import get_logger
from userdatamodel.driver import SQLAlchemyDriver

from fence.models import (
    Project,
    User,
    AccessPrivilege,
    AuthorizationProvider
)

from fence.resources.storage import StorageManager


class DbGapSyncer(object):

    def __init__(
            self, dbGaP, DB, project_mapping,
            storage_credentials=None, db_session=None,
            is_sync_from_dbgap_server=False,
            sync_from_local_csv_dir=None, sync_from_local_yaml_dir=None):
        '''
        Syncs ACL files from dbGap to auth database and storage backends
        Args:
            dbGaP: a dict containing creds to access dbgap sftp
            DB: database connection string
            project_mapping: a dict containing how dbgap ids map to projects
            storage_credentials: a dict containing creds for storage backends
            sync_from_dir: path to an alternative dir to sync from instead of
                           dbGaP
        '''

        self.sync_from_local_csv_dir = sync_from_local_csv_dir
        self.sync_from_local_yaml_dir = sync_from_local_yaml_dir
        self.is_sync_from_dbgap_server = is_sync_from_dbgap_server
        if is_sync_from_dbgap_server:
            self.sftp = dbGaP['sftp']
            self.dbgap_key = dbGaP['decrypt_key']
        self.session = db_session
        self.driver = SQLAlchemyDriver(DB)
        self._projects = dict()
        self.project_mapping = project_mapping
        self.logger = get_logger('dbgap_syncer')

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
        pattern = "authentication_file_phs(\d{6}).csv"
        if encrypted:
            pattern += '.enc$'
        else:
            pattern += '$'
        return (re.match(pattern,
                         os.path.basename(filepath)))

    def _get_from_sftp(self, path):
        """
        Copy all data from sftp to a local dir
        Args:
            path (str): path to local directory
        Returns:
            None
        """
        cnopts = pysftp.CnOpts()
        cnopts.hostkeys = None
        with pysftp.Connection(self.sftp['host'],
                               username=self.sftp['username'],
                               password=self.sftp['password'],
                               cnopts=cnopts) as sftp:
            sftp.get_r('.', path)

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
            p = sp.Popen(
                ["crypt", self.dbgap_key],
                stdin=open(filepath, 'r'),
                stdout=sp.PIPE,
                stderr=open(os.devnull, 'w')
            )
            yield StringIO(p.communicate()[0])
        else:
            f = open(filepath, 'r')
            yield f
            f.close()

    def _sync_csv(self, file_dict, encrypted=True):
        '''
        parse csv files to python dict
        Args:
            fild_dict: a dictionary with key(file path) and value(privileges)
            encrypted: whether those files are encrypted
        Return:
             phsids: a nested dict of
            {
                username: {
                    phsid1: ['read-storage','write-storage'],
                    phsid2: ['read-storage'],
                    }
            }
            userinfo: a dict of {username: {'email': email}}    

        '''
        phsids = dict()
        userinfo = dict()
        for filepath, privileges in file_dict.iteritems():
            if os.stat(filepath).st_size == 0:
                continue
            if self._match_pattern(filepath, encrypted=encrypted):
                with self._read_file(filepath, encrypted=encrypted) as f:
                    csv = DictReader(f, quotechar='"', skipinitialspace=True)
                    for row in csv:
                        username = row['login']
                        phsid_privileges = defaultdict(set)
                        [phsid_privileges[row['phsid'].split('.')[0]].add(
                            privilege) for privilege in privileges]

                        if username in phsids:
                            phsids[username].update(phsid_privileges)
                        else:
                            phsids[username] = phsid_privileges

                        userinfo[username] = {
                            'email': row['email']}

        return phsids, userinfo

    def _sync_yaml(self, file_list, encrypted=True):
        '''
        parse yaml files to python nested dictionary
        Args:
            file_list: list of yaml file
            encrypted: whether those files are encrypted
        Returns:
            phsids: a nested dict of
            {
                username: {
                    phsid1: ['read-storage','write-storage'],
                    phsid2: ['read-storage'],
                    }
            }
            userinfo: a dict of {username: {'email': email}}

        '''
        phsids = dict()
        userinfo = dict()
        for filepath in file_list:
            if os.stat(filepath).st_size == 0:
                continue
            with self._read_file(filepath, encrypted=encrypted) as stream:
                data = yaml.safe_load(stream)
                users = data['users']
                for username, projects in users.iteritems():
                    phsid_privileges = defaultdict(set)

                    try:
                        for project in projects['projects']:
                            phsid_privileges[project['auth_id']
                                             ] = project['privilege']
                    except KeyError:
                        continue

                    userinfo[username] = {
                        'email': username}
                    if not username in phsids:
                        phsids[username] = (phsid_privileges)
                    else:
                        phsids[username].add(phsid_privileges)
        return phsids, userinfo

    @classmethod
    def sync_two_userinfo_dict(self, userinfo1, userinfo2):
        '''
        merge userinfo1 into userinfo2
        Args:
            userinfo1, userinfo2: nested dicts of {username: {'email': 'abc@email.com'}}
        Returns:
            None
        '''
        for user, info1 in userinfo1.iteritems():
            info2 = userinfo2.get(user)
            if not info2:
                userinfo2.update({user: info1})
                continue
            userinfo2[user].update(info1)

    @classmethod
    def sync_two_phsids_dict(self, phsids1, phsids2):
        '''
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
        '''
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

    def sync_to_db_and_storage_backend(self, phsids, userinfo, sess):
        '''
        sync user access control to database and storage backend
        Args:
            phsids: a dictionary of {username: {phsid: ['read-storage','write-storage']}
            userinfo: a dictionary of {username: userinfo{}}
            sess: a sqlalchemy session
        Return:
            None
        '''
        self._init_projects(sess)
        auth_provider = self._get_or_create(
            sess, AuthorizationProvider, name='dbGaP')

        privilege_list = {
            (ua.user.username, ua.project.auth_id) for
            ua in sess.query(AccessPrivilege)
            .filter_by(auth_provider=auth_provider).all()}

        list_from_dbgap = set()
        map_from_backend_to_dbgap = dict()
        for username, projects in phsids.iteritems():
            for phsid, _ in projects.iteritems():
                for project in self.project_mapping[phsid]:
                    list_from_dbgap.add(
                        (username, project['auth_id']))
                    map_from_backend_to_dbgap[project['auth_id']] = phsid

        to_delete = set.difference(privilege_list, list_from_dbgap)
        to_add = set.difference(list_from_dbgap, privilege_list)
        self._revoke_from_storage(to_delete)
        self._revoke_from_db(sess, to_delete, auth_provider)
        self._grant_from_storage(to_add, map_from_backend_to_dbgap, phsids)
        self._grant_from_db(sess, userinfo, to_add,
                            map_from_backend_to_dbgap, phsids, auth_provider)

    def _revoke_from_db(self, s, to_delete, auth_provider):
        '''
        Revoke user access to projects in the auth database
        Args:
            s: sqlalchemy session
            to_delete: a set of (username, project.auth_id) to be revoked from db
        Return:
            None
        '''

        for (username, project_auth_id) in to_delete:
            q = (s.query(AccessPrivilege)
                 .filter(AccessPrivilege.user.has(username=username))
                 .filter(AccessPrivilege.project.has(auth_id=project_auth_id))
                 .filter_by(auth_provider=auth_provider)
                 .all())
            for access in q:
                self.logger.info(
                    "revoke {} access to {} in db"
                    .format(username, project_auth_id))
                s.delete(access)

    def _grant_from_db(self, s, userinfo, to_add, map_from_backend_to_dbgap, phsids, auth_provider):
        '''
        Grant user access to projects in the auth database
        Args:
            s: sqlalchemy session
            to_add: a set of (username, project.auth_id) to be granted
            map_from_backend_to_dbgap: a dictinary to obtain dbgap_project_id from backend_auth_id
            phsids: a dictionary of {username: {phsid: ['read-storage','write-storage']}
        Return:
            None
        '''
        for (username, project_auth_id) in to_add:
            u = s.query(User).filter(User.username == username).first()
            if not u:
                self.logger.info('create user {}'.format(username))
                u = User(username=username)
            u.email = userinfo[username]['email']
            s.add(u)
            self.logger.info(
                'grant {} access to {} in db'
                .format(username, project_auth_id)
            )

            user_access = AccessPrivilege(
                user=u,
                project=self._projects[project_auth_id],
                privilege=list(
                    phsids[username][map_from_backend_to_dbgap[project_auth_id]]),
                auth_provider=auth_provider)
            s.add(user_access)

    def _revoke_from_storage(self, to_delete):
        '''
        If a project have storage backend,
        revoke user's access to buckets in the storage backend
        Args:
            to_delete: a set of (username, project.auth_id) to be revoked
        Return:
            None
        '''
        for (username, project_auth_id) in to_delete:
            project = self._projects[project_auth_id]
            for sa in project.storage_access:
                self.logger.info(
                    'revoke {} access to {} in {}'
                    .format(username, project, sa.provider.name))
                self.storage_manager.revoke_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project
                )

    def _grant_from_storage(self, to_add, map_from_backend_to_dbgap, phsids):
        '''
        If a project have storage backend,
        grant user's access to buckets in the storage backend
        Args:
            to_add: a set of (username, project.auth_id)  to be granted
            map_from_backend_to_dbgap: a dictinary to obtain dbgap_project_id from backend_auth_id
            phsids: a dictionary of {username: {phsid: ['read-storage','write-storage']}
        Return:
            None
        '''

        for (username, project_auth_id) in to_add:
            project = self._projects[project_auth_id]
            for sa in project.storage_access:
                self.logger.info(
                    'grant {} access to {} in {}'
                    .format(username, project, sa.provider.name))

                dbgap_project_id = map_from_backend_to_dbgap[project_auth_id]
                access = list(phsids[username][dbgap_project_id])
                self.storage_manager.grant_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project,
                    access=access
                )

    def _init_projects(self, s):
        for projects in self.project_mapping.values():
            for p in projects:
                project = self._get_or_create(s, Project, **p)
                self._projects[project.auth_id] = project

    def _get_or_create(self, s, model, **kwargs):
        instance = s.query(model).filter_by(**kwargs).first()
        if not instance:
            instance = model(**kwargs)
            s.add(instance)
        return instance

    def sync(self):
        if self.session:
            self._sync(self.session)
        else:
            with self.driver.session as s:
                self._sync(s)

    def _sync(self, s):
        '''
        Collect files from dbgap server
        sync csv and yaml files to storage backend and fence DB

        '''
        dbgap_file_list = []
        tmpdir = tempfile.mkdtemp()
        if self.is_sync_from_dbgap_server:
            self._get_from_sftp(tmpdir)
            dbgap_file_list = glob.glob(os.path.join(tmpdir, '*'))

        phsids1, userinfo1 = self._sync_csv(
            dict(zip(dbgap_file_list, [
                 ['read-storage']]*len(dbgap_file_list))),
            encrypted=False)

        try:
            shutil.rmtree(tmpdir)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise

        local_csv_file_list = []
        if self.sync_from_local_csv_dir:
            local_csv_file_list = glob.glob(
                os.path.join(self.sync_from_local_csv_dir, '*'))

        phsids2, userinfo2 = self._sync_csv(
            dict(zip(local_csv_file_list, [
                 ['read-storage']]*len(local_csv_file_list))),
            encrypted=False)

        import pdb
        pdb.set_trace()

        local_yaml_file_list = []
        if self.sync_from_local_yaml_dir:
            local_yaml_file_list = glob.glob(
                os.path.join(self.sync_from_local_yaml_dir, '*'))

        phsids3, userinfo3 = self._sync_yaml(
            local_yaml_file_list, encrypted=False)

        # privilleges in yaml files overide ones in csv files
        self.sync_two_phsids_dict(phsids2, phsids1)
        self.sync_two_userinfo_dict(userinfo2, userinfo1)

        self.sync_two_phsids_dict(phsids3, phsids1)
        self.sync_two_userinfo_dict(userinfo3, userinfo1)

        self.sync_to_db_and_storage_backend(phsids1, userinfo1, s)


if __name__ == '__main__':

    from cdisutilstest.code.storage_client_mock import get_client
    from ..local_settings import DB, dbGaP, STORAGE_CREDENTIALS

    from mock import patch
    import sys
    import yaml

    import argparse

    parser = argparse.ArgumentParser(description='Syncing dbgap')

    parser.add_argument(
        '--projects',
        dest='project_mapping',
        help='Specify project mapping yaml file')

    parser.add_argument(
        '--yaml-input',
        dest='yaml_path',
        help='Specify yaml file directory')

    parser.add_argument(
        '--csv-input',
        dest='csv_path',
        help='specify csv file directory')

    parser.add_argument(
        '--ftp-sync ',
        dest='is_sync_from_dbgap_server',
        type=bool,
        help='sync from server True/False',
        default=False)

    args = parser.parse_args()
    project_mapping = args.project_mapping
    sync_from_local_yaml_dir = args.yaml_path
    sync_from_local_csv_dir = args.csv_path
    is_sync_from_dbgap_server = args.is_sync_from_dbgap_server

    patcher = patch(
        'fence.resources.storage.get_client',
        get_client)
    patcher.start()

    syncer_obj = DbGapSyncer(
        dbGaP={}, DB=DB, project_mapping=project_mapping,
        storage_credentials={'test-cleversafe': {'backend': 'cleversafe'}},
        is_sync_from_dbgap_server=is_sync_from_dbgap_server,
        sync_from_local_csv_dir=sync_from_local_csv_dir, sync_from_local_yaml_dir=sync_from_local_yaml_dir)

    syncer_obj.sync()
