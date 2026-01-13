import os
import time
import jwt
import uuid

from unittest.mock import MagicMock, patch
from yaml import safe_load as yaml_load

from cdislogging import get_logger
from gen3cirrus import GoogleCloudManager
from tests.storageclient.storage_client_mock import (
    get_client,
    StorageClientMocker,
)
import pytest
from userdatamodel import Base
from userdatamodel.models import *
from gen3authz.client.arborist.client import ArboristClient

from fence.config import config
from fence.resources.openid.ras_oauth2 import RASOauth2Client
from fence.auth import login_user_or_require_registration
from fence.sync.sync_users import UserSyncer
from fence.resources import userdatamodel as udm
from fence.models import (
    AccessPrivilege,
    AuthorizationProvider,
    User,
    GA4GHVisaV1,
    create_user,
    User,
)

from tests.conftest import random_txn, NoAsyncMagicMock

logger = get_logger(__name__)

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
def syncer(db_session, request, rsa_private_key, kid):
    # reset GA4GH visas and users table
    db_session.query(User).delete()
    db_session.query(GA4GHVisaV1).delete()
    db_session.commit()

    if request.param == "google":
        backend = "google"
    else:
        backend = "cleversafe"

    backend_name = "test-" + backend
    storage_credentials = {str(backend_name): {"backend": backend}}
    provider = [{"name": backend_name, "backend": backend}]

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
    syncer_obj.arborist_client = NoAsyncMagicMock(ArboristClient)

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

    syncer_obj._create_arborist_resources = MagicMock()

    syncer_obj.arborist_client.revoke_all_policies_for_user = MagicMock()

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

    db_session.commit()

    return syncer_obj


def get_test_encoded_decoded_visa_and_exp(
    db_session,
    user,
    rsa_private_key,
    kid,
    expires=None,
    sub=None,
    make_invalid=False,
):
    """
    user can be a db user object or just a username
    """
    expires = expires or int(time.time()) + 1000
    headers = {"kid": kid}
    sub = sub or "abcde12345aspdij"

    decoded_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": sub,
        "iat": int(time.time()),
        "exp": expires,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": str(uuid.uuid4()),
        "txn": random_txn(),
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1",
            "asserted": int(time.time()),
            "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
            "source": "https://ncbi.nlm.nih.gov/gap",
        },
        "ras_dbgap_permissions": [
            {
                "consent_name": "Health/Medical/Biomedical",
                "phs_id": "phs000991",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": expires,
            },
            {
                "consent_name": "General Research Use (IRB, PUB)",
                "phs_id": "phs000961",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": expires,
            },
            {
                "consent_name": "Disease-Specific (Cardiovascular Disease)",
                "phs_id": "phs000279",
                "version": "v2",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": expires,
            },
            {
                "consent_name": "Health/Medical/Biomedical (IRB)",
                "phs_id": "phs000286",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c3",
                "role": "designated user",
                "expiration": expires,
            },
            {
                "consent_name": "Disease-Specific (Focused Disease Only, IRB, NPU)",
                "phs_id": "phs000289",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c2",
                "role": "designated user",
                "expiration": expires,
            },
            {
                "consent_name": "Disease-Specific (Autism Spectrum Disorder)",
                "phs_id": "phs000298",
                "version": "v4",
                "participant_set": "p3",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": expires,
            },
        ],
    }

    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

    expires = int(decoded_visa["exp"])

    if make_invalid:
        encoded_visa = encoded_visa[: len(encoded_visa) // 2]

    return encoded_visa, decoded_visa, expires


def add_visa_manually(db_session, user, rsa_private_key, kid, expires=None, sub=None):
    expires = expires or int(time.time()) + 1000
    make_invalid = False

    if getattr(user, "username", user) == "expired_visa_user":
        expires -= 100000
    if getattr(user, "username", user) == "invalid_visa_user":
        make_invalid = True
    if getattr(user, "username", user) == "TESTUSERD":
        make_invalid = True

    encoded_visa, decoded_visa, expires = get_test_encoded_decoded_visa_and_exp(
        db_session,
        user,
        rsa_private_key,
        kid,
        expires=expires,
        make_invalid=make_invalid,
        sub=sub,
    )

    visa = GA4GHVisaV1(
        user=user,
        source=decoded_visa["ga4gh_visa_v1"]["source"],
        type=decoded_visa["ga4gh_visa_v1"]["type"],
        asserted=int(decoded_visa["ga4gh_visa_v1"]["asserted"]),
        expires=expires,
        ga4gh_visa=encoded_visa,
    )

    db_session.add(visa)
    db_session.commit()

    return encoded_visa, visa


def fake_ras_login(username, subject, email=None, db_session=None):
    """
    Mock a login by creating a sub/iss mapping in the db and logging them into a
    session.

    Args:
        username (str): Username from IdP
        subject (str): sub id in tokens from IdP
        email (None, optional): email if provided
        db_session (None, optional): db session to use
    """
    ras_client = RASOauth2Client(
        config["OPENID_CONNECT"]["ras"],
        HTTP_PROXY=config["HTTP_PROXY"],
        logger=logger,
    )
    actual_username = ras_client.map_iss_sub_pair_to_user(
        issuer="https://stsstg.nih.gov",
        subject_id=subject,
        username=username,
        email=email,
        db_session=db_session,
    )
    logger.debug(
        f"subject: {subject}, username: {username}, actual_username: {actual_username}"
    )
    is_logged_in = login_user_or_require_registration(
        actual_username, provider="ras", email=None, id_from_idp=subject
    )
    assert is_logged_in

    # todo sub to iss table
