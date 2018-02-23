from collections import defaultdict
from contextlib import contextmanager
from csv import DictReader
import glob
import os
import pysftp
import re
from StringIO import StringIO
import subprocess as sp
import temps

from cdispyutils.log import get_logger
from fence.utils import SQLAlchemyDriver

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
            sync_from_dir=None):
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
        self.sync_from_dir = sync_from_dir
        if sync_from_dir is None:
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
        pattern = "authentication_file_phs(\d{6}).txt"
        if encrypted:
            pattern += '.enc'
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

    def _sync_csv(self, file_list, encrypted=True):
        '''
        parse csv files to python dict
        Args:
            file_list: a list of file paths
            encrypted: whether those files are encrypted
        Return:
            phsids: a dict of {username: [phsids]}
            userinfo: a dict of {username: {email: email}}
        '''
        phsids = defaultdict(set)
        userinfo = dict()
        for filepath in file_list:
            if os.stat(filepath).st_size == 0:
                continue
            if self._match_pattern(filepath, encrypted=encrypted):
                with self._read_file(filepath, encrypted=encrypted) as f:
                    csv = DictReader(f, quotechar='"', skipinitialspace=True)
                    for row in csv:
                        username = row['login']
                        phsid = row['phsid'].split('.')[0]
                        userinfo[username] = {
                            'email': row['email']}
                        phsids[username].add(phsid)
        return phsids, userinfo

    def sync_to_db_and_storage_backend(self, phsids, userinfo, s):
        """
        sync user access control to database and storage backend
        Args:
            phsids: a dictionary of {username: phsids[]}
            userinfo: a dictionary of {username: userinfo{}}
            s: a sqlalchemy session
        Return:
            None

        """
        self._init_projects(s)

        auth_provider = self._get_or_create(
            s, AuthorizationProvider, name='dbGaP')

        privilege_list = {
            (ua.user.username, ua.project.auth_id) for
            ua in s.query(AccessPrivilege)
            .filter_by(auth_provider=auth_provider).all()}

        list_from_dbgap = set()
        for username, ids in phsids.iteritems():
            for phsid in ids:
                for project in self.project_mapping[phsid]:
                    list_from_dbgap.add(
                        (username, project['auth_id']))
        to_delete = set.difference(privilege_list, list_from_dbgap)
        to_add = set.difference(list_from_dbgap, privilege_list)
        self._revoke_from_storage(to_delete)
        self._revoke_from_db(s, to_delete, auth_provider)
        self._grant_from_storage(to_add)
        self._grant_from_db(s, userinfo, to_add, auth_provider)

    def _revoke_from_db(self, s, to_delete, auth_provider):
        '''
        Revoke user access to projects in the auth database
        Args:
            s: sqlalchemy session
            to_add: a set of (username, project.auth_id) to be granted
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

    def _grant_from_db(self, s, userinfo, to_add, auth_provider):
        '''
        Grant user access to projects in the auth database
        Args:
            s: sqlalchemy session
            to_add: a set of (username, project.auth_id) to be granted
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
                privilege=['read-storage'],
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

    def _grant_from_storage(self, to_add):
        '''
        If a project have storage backend,
        grant user's access to buckets in the storage backend
        Args:
            to_add: a set of (username, project.auth_id)  to be granted
        Return:
            None
        '''
        for (username, project_auth_id) in to_add:
            project = self._projects[project_auth_id]
            for sa in project.storage_access:
                self.logger.info(
                    'grant {} access to {} in {}'
                    .format(username, project, sa.provider.name))
                self.storage_manager.grant_access(
                    provider=sa.provider.name,
                    username=username,
                    project=project,
                    access='read-storage'
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
        if self.sync_from_dir is None:
            with temps.tmpdir() as workdir:
                self._get_from_sftp(workdir)
                phsids, userinfo = self._sync_csv(
                    glob.glob(os.path.join(workdir, '*')))
        else:
            phsids, userinfo = self._sync_csv(
                glob.glob(os.path.join(self.sync_from_dir, '*')),
                encrypted=False,
            )
        self.sync_to_db_and_storage_backend(phsids, userinfo, s)


if __name__ == '__main__':

    from cdisutilstest.code.storage_client_mock import get_client
    from ..local_settings import DB, dbGaP, STORAGE_CREDENTIALS

    from mock import patch
    import sys
    import yaml

    patcher = patch(
        'fence.resources.storage.get_client',
        get_client)
    patcher.start()

    project_mapping_path = sys.argv[1]
    with open(project_mapping_path, 'r') as f:
        mapping = yaml.load(f)
    sync_from_dir = sys.argv[2] if len(sys.argv) > 2 else None

    syncer = DbGapSyncer(
        dbGaP, DB, mapping,
        storage_credentials=STORAGE_CREDENTIALS,
        sync_from_dir=sync_from_dir)
    syncer.sync()
