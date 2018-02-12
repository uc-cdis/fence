from mock import patch
import pytest
import os

from cdisutilstest.code.storage_client_mock import get_client
from fence.sync.sync_dbgap import DbGapSyncer
from fence.resources import userdatamodel as udm
from userdatamodel import Base
from userdatamodel.models import *
from userdatamodel.driver import SQLAlchemyDriver

from ..test_settings import DB

DATA_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'data'
)


@pytest.fixture
def syncer(db_session):
    provider = {
        'name': 'test-cleversafe',
        'backend': 'cleversafe'
    }
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
        ]
    }

    # patch storage client
    patcher = patch(
        'fence.resources.storage.get_client',
        get_client)
    patcher.start()

    syncer_obj = DbGapSyncer(
        dbGaP={}, DB=DB, db_session=db_session, project_mapping=project_mapping,
        storage_credentials={'test-cleversafe': {'backend': 'cleversafe'}},
        sync_from_dir=DATA_DIR)

    udm.create_provider(
        db_session, provider['name'],
        backend=provider['backend']
    )
    for project in projects:
        p = udm.create_project_with_dict(db_session, project)
        for sa in project['storage_accesses']:
            for bucket in sa['buckets']:
                syncer_obj.storage_manager.create_bucket(
                    sa['name'], db_session, bucket, p)

    return syncer_obj
