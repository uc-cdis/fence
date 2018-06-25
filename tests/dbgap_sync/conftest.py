import os

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch
from yaml import safe_load as yaml_load

from cirrus import GoogleCloudManager
from cdisutilstest.code.storage_client_mock import (
    get_client, StorageClientMocker
)
from fence.sync.sync_users import UserSyncer
from fence.resources import userdatamodel as udm

from userdatamodel import Base
from userdatamodel.models import *
from userdatamodel.driver import SQLAlchemyDriver

from fence.models import (
    AccessPrivilege,
    AuthorizationProvider,
    User,
)

LOCAL_CSV_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/csv")

LOCAL_YAML_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "data/yaml/user.yaml"
)


@pytest.fixture
def syncer(app, db_session):
    provider = [{
        'name': 'test-cleversafe',
        'backend': 'cleversafe'
    },
    ]

    users = [
        {"username": "TESTUSERB", "is_admin": True, "email": "userA@gmail.com"},
        {"username": "USER_1", "is_admin": True, "email": "user1@gmail.com"},
        {
            "username": "test_user1@gmail.com",
            "is_admin": False,
            "email": "test_user1@gmail.com",
        },
        {
            "username": "deleted_user@gmail.com",
            "is_admin": True,
            "email": "deleted_user@gmail.com",
        },
        {"username": "TESTUSERD", "is_admin": True, "email": "userD@gmail.com"},
    ]

    projects = [
        {
            "auth_id": "TCGA-PCAWG",
            "storage_accesses": [{"buckets": ["test-bucket"], "name": backend_name}],
        },
        {
            "auth_id": "phs000178",
            "name": "TCGA",
            "storage_accesses": [{"buckets": ["test-bucket2"], "name": backend_name}],
        },
        {
            "auth_id": "phs000179",
            "name": "BLAH",
            "storage_accesses": [{"buckets": ["test-bucket3"], "name": backend_name}],
        },
    ]
    project_mapping = {
        "phs000178": [
            {"name": "TCGA", "auth_id": "phs000178"},
            {"name": "TCGA-PCAWG", "auth_id": "TCGA-PCAWG"},
        ],
        "phs000179": [{"name": "BLAH", "auth_id": "phs000179"}],
        "phstest": [{"name": "Test", "auth_id": "Test"}],
    }

    dbGap = {}
    test_db = yaml_load(
        open(os.path.join(
               os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
               'test-fence-config.yaml'))
    ).get('DB')

    syncer_obj = UserSyncer(
        dbGaP=dbGap, DB=test_db, db_session=db_session, project_mapping=project_mapping,
        storage_credentials=storage_credentials,
        is_sync_from_dbgap_server=False,
        sync_from_local_csv_dir=LOCAL_CSV_DIR,
        sync_from_local_yaml_file=LOCAL_YAML_DIR,
    )
    syncer_obj.arborist_client = MagicMock(ArboristClient)
    syncer_obj.arborist_client.get_policy.side_effect = lambda _: None

    for element in provider:
        udm.create_provider(db_session, element["name"], backend=element["backend"])

    test_projects = []
    for project in projects:
        p = udm.create_project_with_dict(db_session, project)
        test_projects.append(p)
        for sa in project["storage_accesses"]:
            for bucket in sa["buckets"]:
                syncer_obj.storage_manager.create_bucket(
                    sa["name"], db_session, bucket, p
                )

    for user in users:
        db_session.add(User(**user))

    db_session.commit()

    return syncer_obj
