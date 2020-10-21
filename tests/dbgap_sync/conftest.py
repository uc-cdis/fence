import os

from unittest.mock import MagicMock, patch
from yaml import safe_load as yaml_load

from cirrus import GoogleCloudManager
from cdisutilstest.code.storage_client_mock import get_client, StorageClientMocker
import pytest
from userdatamodel import Base
from userdatamodel.models import *
from userdatamodel.driver import SQLAlchemyDriver

from fence.sync.sync_users import UserSyncer
from fence.resources import userdatamodel as udm

from fence.models import AccessPrivilege, AuthorizationProvider, User

from gen3authz.client.arborist.client import ArboristClient

LOCAL_CSV_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/csv")

LOCAL_YAML_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "data/yaml/user.yaml"
)


@pytest.fixture
def storage_client():
    """
    Fixture to patch the StorageClientMocker methods so we can test if they
    get called and what args they get called with.

    This patches the functions we want to test in StorageClientMocker. This
    DOES NOT actually patch the entire function call though, we STILL CALL
    the function in StorageClientMocker.

    The purpose of this fixture is a wrapper so we can check
    calls into StorageClientMocker, it doesn't change functionality.
    """
    storage_client_mock = MagicMock()

    # ensure storage client is patched
    patcher = patch("fence.resources.storage.get_client", get_client)
    patcher.start()

    storage_client_mock.return_value.get_user = patch.object(
        StorageClientMocker, "get_user", side_effect=StorageClientMocker.get_user
    )

    storage_client_mock.return_value.get_or_create_user = patch.object(
        StorageClientMocker,
        "get_or_create_user",
        side_effect=StorageClientMocker.get_or_create_user,
    )

    storage_client_mock.return_value.add_bucket_acl = patch.object(
        StorageClientMocker,
        "add_bucket_acl",
        side_effect=StorageClientMocker.add_bucket_acl,
    )

    storage_client_mock.return_value.delete_bucket = patch.object(
        StorageClientMocker,
        "delete_bucket",
        side_effect=StorageClientMocker.delete_bucket,
    )

    return storage_client_mock


@pytest.fixture
def syncer(db_session, request):
    if request.param == "google":
        backend = "google"
    else:
        backend = "cleversafe"

    backend_name = "test-" + backend
    storage_credentials = {str(backend_name): {"backend": backend}}
    provider = [{"name": backend_name, "backend": backend}]

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

    dbGap = yaml_load(
        open(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "test-fence-config.yaml",
            )
        )
    ).get("dbGaP")
    test_db = yaml_load(
        open(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "test-fence-config.yaml",
            )
        )
    ).get("DB")

    syncer_obj = UserSyncer(
        dbGaP=dbGap,
        DB=test_db,
        db_session=db_session,
        project_mapping=project_mapping,
        storage_credentials=storage_credentials,
        is_sync_from_dbgap_server=False,
        sync_from_local_csv_dir=LOCAL_CSV_DIR,
        sync_from_local_yaml_file=LOCAL_YAML_DIR,
    )
    syncer_obj.arborist_client = MagicMock(ArboristClient)

    def mocked_update(parent_path, resource, **kwargs):
        resource["tag"] = "123456"
        resource["subresources"] = [
            subresource.get("name", subresource.get("path", "").lstrip("/"))
            for subresource in resource.get("subresources", [])
            if subresource.get("name", subresource.get("path", "").lstrip("/"))
        ]
        response = {"updated": resource}
        return response

    def mocked_get(path, **kwargs):
        return None

    syncer_obj.arborist_client.update_resource = MagicMock(side_effect=mocked_update)

    syncer_obj.arborist_client.get_resource = MagicMock(side_effect=mocked_get)

    syncer_obj.arborist_client.get_policy.side_effect = lambda _: None

    syncer_obj.arborist_client._user_url = "/user"

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
