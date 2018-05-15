from mock import patch
import pytest
import os

from cdisutilstest.code.storage_client_mock import get_client
from fence.sync.sync_users import UserSyncer
from fence.resources import userdatamodel as udm
from userdatamodel import Base
from userdatamodel.models import *
from userdatamodel.driver import SQLAlchemyDriver

from ..test_settings import DB

from fence.models import (
    AccessPrivilege,
    AuthorizationProvider,
    User,
)

LOCAL_CSV_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'data/csv'
)

LOCAL_YAML_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'data/yaml/user.yaml'
)


@pytest.fixture
def syncer(db_session):
    provider = [{
        'name': 'test-cleversafe',
        'backend': 'cleversafe'
    },
    ]

    users = [
        {'username': 'TESTUSERB', 'is_admin': True, 'email': 'userA@gmail.com'},
        {'username': 'USER_1', 'is_admin': True, 'email': 'user1@gmail.com'},
        {'username': 'test_user1@gmail.com', 'is_admin': False,
            'email': 'test_user1@gmail.com'},
        {'username': 'deleted_user@gmail.com',
            'is_admin': False, 'email': 'deleted_user@gmail.com'},
        {'username': 'TESTUSERD', 'is_admin': True, 'email': 'userD@gmail.com'}
    ]

    projects = [
        {'auth_id': 'TCGA-PCAWG',
         'storage_accesses': [{'buckets': ['test-bucket'],
                               'name': 'test-cleversafe'}]},
        {'auth_id': 'phs000178',
         'name': 'TCGA',
         'storage_accesses': [{'buckets': ['test-bucket2'],
                               'name': 'test-cleversafe'}]},
        {'auth_id': 'phs000179',
         'name': 'BLAH',
         'storage_accesses': [{'buckets': ['test-bucket3'],
                               'name': 'test-cleversafe'}]}
    ]
    project_mapping = {
        'phs000178': [
            {'name': 'TCGA', 'auth_id': 'phs000178'},
            {'name': 'TCGA-PCAWG', 'auth_id': 'TCGA-PCAWG'}
        ],
        'phs000179': [
            {'name': 'BLAH', 'auth_id': 'phs000179'}
        ],
        'phstest': [
            {'name': 'Test', 'auth_id': 'Test'}
        ]
    }

    dbGap = {}

    # patch storage client
    patcher = patch(
        'fence.resources.storage.get_client',
        get_client)
    patcher.start()

    syncer_obj = UserSyncer(
        dbGaP=dbGap, DB=DB, db_session=db_session, project_mapping=project_mapping,
        storage_credentials={'test-cleversafe': {'backend': 'cleversafe'}},
        is_sync_from_dbgap_server=False,
        sync_from_local_csv_dir=LOCAL_CSV_DIR,
        sync_from_local_yaml_file=LOCAL_YAML_DIR)

    for element in provider:
        udm.create_provider(
            db_session, element['name'],
            backend=element['backend']
        )

    test_projects = []
    for project in projects:
        p = udm.create_project_with_dict(db_session, project)
        test_projects.append(p)
        for sa in project['storage_accesses']:
            for bucket in sa['buckets']:
                syncer_obj.storage_manager.create_bucket(
                    sa['name'], db_session, bucket, p)
    test_users = []
    for u in users:
        user = User(**u)
        test_users.append(user)
        db_session.add(user)

    auth_providers = [AuthorizationProvider(name='dbGaP'), AuthorizationProvider(name='fence')]

    access = AccessPrivilege(user=test_users[0], project=test_projects[0],
                             auth_provider=auth_providers[1],
                             privilege=['read-storage', 'write-storage'])
    db_session.add(access)

    access = AccessPrivilege(user=test_users[1], project=test_projects[0],
                             auth_provider=auth_providers[1],
                             privilege=['read-storage', 'write-storage'])
    db_session.add(access)

    access = AccessPrivilege(user=test_users[2], project=test_projects[0],
                             auth_provider=auth_providers[1],
                             privilege=['read', 'read-storage', 'write-storage'])
    db_session.add(access)

    access = AccessPrivilege(user=test_users[2], project=test_projects[1],
                             auth_provider=auth_providers[1],
                             privilege=['read', 'write', 'upload', 'read-storage', 'write-storage'])
    
    access = AccessPrivilege(user=test_users[4], project=test_projects[2],
                             auth_provider=auth_providers[0],
                             privilege=['read-storage'])

    db_session.add(access)

    db_session.commit()

    return syncer_obj
