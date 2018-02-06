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
def syncer(request):
    db = SQLAlchemyDriver(DB)

    def fin():
        print 'delete all'
        for tbl in reversed(Base.metadata.sorted_tables):
            db.engine.execute(tbl.delete())
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
        dbGaP={}, DB=DB, project_mapping=project_mapping,
        storage_credentials={'test-cleversafe': {'backend': 'cleversafe'}},
        sync_from_dir=DATA_DIR)

    with db.session as s:
        udm.create_provider(
            s, provider['name'],
            backend=provider['backend']
        )
        for project in projects:
            p = udm.create_project_with_dict(s, project)
            for sa in project['storage_accesses']:
                for bucket in sa['buckets']:
                    syncer_obj.storage_manager.create_bucket(
                        sa['name'], s, bucket, p)

    request.addfinalizer(fin)
    return syncer_obj
