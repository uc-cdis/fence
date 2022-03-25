# pylint: disable=redefined-outer-name
"""
Define pytest fixtures.
TODO (rudyardrichter, 2018-11-06): clean up/consolidate indexd response mocks
"""

from collections import OrderedDict
import json
import os
import copy
import time
from datetime import datetime
import mock

from addict import Dict
from authutils.testing.fixtures import (
    _hazmat_rsa_private_key,
    _hazmat_rsa_private_key_2,
    rsa_private_key,
    rsa_private_key_2,
    rsa_public_key,
    rsa_public_key_2,
)
from cryptography.fernet import Fernet
import bcrypt
from cdisutilstest.code.storage_client_mock import get_client
import jwt
from mock import patch, MagicMock, PropertyMock
import pytest
import requests
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.schema import DropTable

import fence
from fence import app_init
from fence import models
from fence.jwt.keys import Keypair
from fence.config import config
from fence.errors import NotFound
from fence.resources.openid.microsoft_oauth2 import MicrosoftOauth2Client

import tests
from tests import test_settings
from tests import utils
from tests.utils.oauth2.client import OAuth2TestClient


@compiles(DropTable, "postgresql")
def _compile_drop_table(element, compiler, **kwargs):
    return compiler.visit_drop_table(element) + " CASCADE"


# Allow authlib to use HTTP for local testing.
os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"


# all the IDPs we want to test.
# any newly added custom OIDC IDP should be added here.
# generic OIDC IDPs should start with "generic" so the tests work.
LOGIN_IDPS = [
    "fence",
    "google",
    "shib",
    "orcid",
    "synapse",
    "microsoft",
    "okta",
    "cognito",
    "ras",
    "cilogon",
    "generic1",
    "generic2",
]


def mock_get_bucket_location(self, bucket, config):
    return "us-east-1"


@pytest.fixture(scope="session")
def claims_refresh():
    new_claims = tests.utils.default_claims()
    new_claims["pur"] = "refresh"
    return new_claims


@pytest.fixture(scope="session")
def encoded_jwt(kid, rsa_private_key):
    """
    Return an example JWT containing the claims and encoded with the private
    key.
    Args:
        rsa_private_key (str): fixture
    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {"kid": kid}
    return jwt.encode(
        utils.default_claims(), key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")


@pytest.fixture(scope="session")
def encoded_jwt_expired(kid, rsa_private_key):
    """
    Return an example JWT that has already expired.
    Args:
        rsa_private_key (str): fixture
    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {"kid": kid}
    claims_expired = utils.default_claims()
    # Move `exp` and `iat` into the past.
    claims_expired["exp"] -= 10000
    claims_expired["iat"] -= 10000
    return jwt.encode(
        claims_expired, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")


@pytest.fixture(scope="session")
def encoded_jwt_refresh_token(claims_refresh, kid, rsa_private_key):
    """
    Return an example JWT refresh token containing the claims and encoded with
    the private key.
    Args:
        claims_refresh (dict): fixture
        rsa_private_key (str): fixture
    Return:
        str: JWT refresh token containing claims encoded with private key
    """
    headers = {"kid": kid}
    return jwt.encode(
        claims_refresh, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")


class Mocker(object):
    def mock_functions(self):
        self.patcher = patch("fence.resources.storage.get_client", get_client)
        self.auth_patcher = patch(
            "fence.resources.storage.StorageManager.check_auth",
            lambda cls, backend, user: True,
        )
        self.boto_patcher = patch(
            "fence.resources.aws.boto_manager.BotoManager.get_bucket_region",
            mock_get_bucket_location,
        )
        self.blob_client_patcher = patch(
            "fence.BlobServiceClient",
            return_value=FakeBlobServiceClient(),
        )
        self.patcher.start()
        self.auth_patcher.start()
        self.boto_patcher.start()
        self.blob_client_patcher.start()
        self.additional_patchers = []

    def unmock_functions(self):
        self.patcher.stop()
        self.auth_patcher.stop()
        self.boto_patcher.stop()
        self.blob_client_patcher.stop()
        for patcher in self.additional_patchers:
            patcher.stop()

    def add_mock(self, patcher):
        patcher.start()
        self.additional_patchers.append(patcher)


class FakeAzureCredential:
    """
    Fake Azure Credential for connecting to Fake Azure Storage
    """

    def __init__(self):
        self.account_key = "FakefakeAccountKey"


class FakeBlobServiceClient:
    """
    Fake blob service client for fence.blueprints.data.indexd.BlobServiceClient
    """

    def __init__(self):
        self.account_name = "fakeAccountName"
        self.credential = FakeAzureCredential()

    @classmethod
    def from_connection_string(cls, conn_str, credential=None, **kwargs):
        """
        Fake method to get a blob service client from a connection string
        """
        return FakeBlobServiceClient()

    @classmethod
    def list_containers(cls):
        """
        Fake method to get a list of containers
        """

        container_names = ["a", "b", "c"]
        return_value = []
        for container_name in container_names:
            mock_object = MagicMock()
            mock_object.name = container_name
            return_value.append(mock_object)

        return return_value

    @classmethod
    def get_container_client(self, container_name):
        """
        Fake method to get a container service client
        """
        return FakeContainerServiceClient(container_name=container_name)


class FakeContainerServiceClient:
    """
    Fake Container Service Client for FakeBlobServiceClient e.g. for AzureBlobServiceClient
    """

    def __init__(self, container_name):
        self.container_name = container_name

    def exists(self):
        """
        check if container exists
        """
        return self.container_name in ["a", "c"]

    def get_container_properties(self):
        """
        get container properties
        """
        return {
            "name": self.container_name,
            "last_modified": datetime.utcnow(),
            "public_access": None,
        }


@pytest.fixture(scope="session")
def kid():
    """Return a JWT key ID to use for tests."""
    return "test-keypair"


@pytest.fixture(scope="session")
def kid_2():
    """Return a second JWT key ID to use for tests."""
    return "test-keypair-2"


@pytest.fixture(scope="function")
def mock_arborist_requests(request):
    """
    This fixture returns a function which you call to mock out arborist endopints.
    Give it an argument in this format:
        {
            "arborist/health": {
                "GET": ("", 200)
            },
            "arborist/auth/request": {
                "POST": ({"auth": False}, 403)
            }
        }
    """

    def do_patch(urls_to_responses=None):
        urls_to_responses = urls_to_responses or {}
        defaults = {"arborist/health": {"GET": ("", 200)}}
        defaults.update(urls_to_responses)
        urls_to_responses = defaults

        def response_for(method, url, *args, **kwargs):
            method = method.upper()
            mocked_response = MagicMock(requests.Response)
            if url not in urls_to_responses:
                mocked_response.status_code = 404
                mocked_response.text = "NOT FOUND"
            elif method not in urls_to_responses[url]:
                mocked_response.status_code = 405
                mocked_response.text = "METHOD NOT ALLOWED"
            else:
                content, code = urls_to_responses[url][method]
                mocked_response.status_code = code
                if isinstance(content, dict):
                    mocked_response.json.return_value = content
                else:
                    mocked_response.text = content
            return mocked_response

        mocked_method = MagicMock(side_effect=response_for)
        patch_method = mock.patch(
            "gen3authz.client.arborist.client.httpx.Client.request", mocked_method
        )

        patch_method.start()
        request.addfinalizer(patch_method.stop)

    return do_patch


@pytest.fixture(scope="session")
def app(kid, rsa_private_key, rsa_public_key):
    """
    Flask application fixture.
    """
    mocker = Mocker()
    mocker.mock_functions()

    root_dir = os.path.dirname(os.path.realpath(__file__))

    # delete the record operation from the data blueprint, because right now it calls a
    # whole bunch of stuff on the arborist client to do some setup for the uploader role
    fence.blueprints.data.blueprint.deferred_functions = [
        f
        for f in fence.blueprints.data.blueprint.deferred_functions
        if f.__name__ != "record"
    ]
    app_init(
        fence.app,
        test_settings,
        root_dir=root_dir,
        config_path=os.path.join(root_dir, "test-fence-config.yaml"),
    )

    # We want to set up the keys so that the test application can load keys
    # from the test keys directory, but the default keypair used will be the
    # one using the fixtures. So, stick the keypair at the front of the
    # keypairs list and reverse the ordered dictionary of public keys after
    # inserting the fixture keypair.
    fixture_keypair = Keypair(
        kid=kid, public_key=rsa_public_key, private_key=rsa_private_key
    )
    fence.app.keypairs = [fixture_keypair] + fence.app.keypairs
    fence.app.jwt_public_keys[config["BASE_URL"]][kid] = rsa_public_key
    fence.app.jwt_public_keys[config["BASE_URL"]] = OrderedDict(
        reversed(list(fence.app.jwt_public_keys[config["BASE_URL"]].items()))
    )

    config.update(BASE_URL=config["BASE_URL"])
    config.update(ENCRYPTION_KEY=Fernet.generate_key().decode("utf-8"))

    yield fence.app

    mocker.unmock_functions()


@pytest.fixture(scope="function")
def auth_client(request):
    """
    Flask application fixture.
    """
    config["MOCK_AUTH"] = False

    def reset_authmock():
        config["MOCK_AUTH"] = True

    request.addfinalizer(reset_authmock)


@pytest.fixture(scope="function")
def test_user_a(db_session):
    test_user = db_session.query(models.User).filter_by(username="test_a").first()
    if not test_user:
        test_user = models.User(username="test_a", is_admin=False)
        db_session.add(test_user)
        db_session.commit()
    return Dict(username="test_a", user_id=test_user.id)


@pytest.fixture(scope="function")
def test_user_b(db_session):
    test_user = db_session.query(models.User).filter_by(username="test_b").first()
    if not test_user:
        test_user = models.User(username="test_b", is_admin=False)
        db_session.add(test_user)
        db_session.commit()
    return Dict(username="test_b", user_id=test_user.id)


@pytest.fixture(scope="function")
def test_user_long(db_session):
    test_user = (
        db_session.query(models.User)
        .filter_by(username="test_amazing_user_with_an_fancy_but_extremely_long_name")
        .first()
    )
    if not test_user:
        test_user = models.User(
            username="test_amazing_user_with_an_fancy_but_extremely_long_name",
            is_admin=False,
        )
        db_session.add(test_user)
        db_session.commit()
    return Dict(
        username="test_amazing_user_with_an_fancy_but_extremely_long_name",
        user_id=test_user.id,
    )


@pytest.fixture(scope="session")
def db(app, request):
    """
    Define pytest fixture for database engine (session-scoped).
    When the tests are over, drop everything from the test database.
    """

    def drop_all():
        models.Base.metadata.drop_all(app.db.engine)

    request.addfinalizer(drop_all)

    return app.db


@fence.app.route("/protected")
@fence.auth.login_required({"access"})
def protected_endpoint(methods=["GET"]):
    """
    Add a protected endpoint to the app for testing.
    """
    return "Got to protected endpoint"


@pytest.fixture(scope="function")
def user_client(db_session):
    users = dict(json.loads(utils.read_file("resources/authorized_users.json")))
    user_id, username = utils.create_user(users, db_session, is_admin=True)
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope="function")
def unauthorized_user_client(db_session):
    users = dict(json.loads(utils.read_file("resources/unauthorized_users.json")))
    user_id, username = utils.create_user(users, db_session, is_admin=True)
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope="function")
def awg_users(db_session):
    awg_usr = dict(json.loads(utils.read_file("resources/awg_user.json")))
    user_id, username = utils.create_awg_user(awg_usr, db_session)


@pytest.fixture(scope="function")
def providers(db_session, app):
    providers = dict(json.loads(utils.read_file("resources/providers.json")))
    utils.create_providers(providers, db_session)


@pytest.fixture(scope="function")
def awg_groups(db_session):
    awg_grps = dict(json.loads(utils.read_file("resources/awg_groups.json")))
    utils.create_awg_groups(awg_grps, db_session)


@pytest.fixture(scope="function")
def db_session(db, patch_app_db_session):
    """
    Define fixture for database session (function-scoped).
    At the end of the function, roll back the session to its initial state.
    """
    connection = db.engine.connect()
    transaction = connection.begin()
    session = db.Session(bind=connection)

    patch_app_db_session(session)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="function")
def oauth_user(app, db_session):
    users = dict(json.loads(utils.read_file("resources/authorized_users.json")))
    user_id, username = utils.create_user(users, db_session, is_admin=True)
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope="function")
def unauthorized_oauth_user(app, db_session):
    users = dict(json.loads(utils.read_file("resources/unauthorized_users.json")))
    user_id, username = utils.create_user(users, db_session, is_admin=True)
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope="function")
def indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()
    record = {}

    protocol = "s3"
    if hasattr(request, "param"):
        protocol = request.param

    if protocol == "gs":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["gs://bucket1/key"],
            "hashes": {},
            "metadata": {"acls": "phs000178,phs000218"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "gs_acl":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["gs://bucket1/key"],
            "hashes": {},
            "acl": ["phs000178", "phs000218"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "s3_acl":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket1/key"],
            "hashes": {},
            "acl": ["phs000178", "phs000218"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "s3_external":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file2",
            "urls": ["s3://bucket2/key"],
            "hashes": {},
            "acl": ["phs000178", "phs000218"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "s3_assume_role":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket5/key"],
            "hashes": {},
            "metadata": {"acls": "phs000178,phs000218"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "no_urls":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file2",
            "urls": [],
            "hashes": {},
            "acl": ["phs000178", "phs000218"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "az":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file2",
            # send to indexd as "az://fakeaccount.blob.core.windows.net/container5/blob6"
            # as fence will convert to "https://fakeaccount.blob.core.windows.net/container5/blob6"
            "urls": ["az://fakeaccount.blob.core.windows.net/container5/blob6"],
            "hashes": {},
            "acl": ["phs000178", "phs000218"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "https":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file2",
            "urls": ["https://fakeaccount/container5/blob6"],
            "hashes": {},
            "acl": ["phs000178", "phs000218"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "nonexistent_guid":
        # throw an error when requested to simulate the GUID not existing
        # TODO (rudyardrichter, 2018-11-03): consolidate things needing to do this patch
        mock = PropertyMock(side_effect=NotFound("no guid"))
        indexd_patcher = patch(
            "fence.blueprints.data.indexd.IndexedFile.index_document", mock
        )
        blank_patcher = patch(
            "fence.blueprints.data.indexd.BlankIndex.index_document", mock
        )
        mocker.add_mock(indexd_patcher)
        mocker.add_mock(blank_patcher)

        output = {"mocker": mocker, "indexed_file_location": None}

        yield output

        mocker.unmock_functions()

        return
    else:
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket1/key"],
            "hashes": {},
            "metadata": {"acls": "phs000178,phs000218"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }

    mock_blob_client_patcher = patch(
        "fence.blueprints.data.indexd.BlobServiceClient",
        return_value=FakeBlobServiceClient(),
    )
    mock_generate_blob_sas_patcher = patch(
        "fence.blueprints.data.indexd.generate_blob_sas",
        return_value="FAKE_SharedAccessSignature_STRING",
    )

    # TODO (rudyardrichter, 2018-11-03): consolidate things needing to do this patch
    indexd_patcher = patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", record
    )
    blank_patcher = patch(
        "fence.blueprints.data.indexd.BlankIndex.index_document", record
    )
    mocker.add_mock(indexd_patcher)
    mocker.add_mock(blank_patcher)
    mocker.add_mock(mock_blob_client_patcher)
    mocker.add_mock(mock_generate_blob_sas_patcher)

    if record and record.get("urls") and len(record["urls"]) > 0:
        output = {
            "mocker": mocker,
            # only gs or s3 for location, ignore specifiers after the _
            "indexed_file_location": protocol.split("_")[0],
            # pass URL for use with underlying indexed file location
            "url": record["urls"][0],
        }
    else:
        output = {
            "mocker": mocker,
            # only gs or s3 for location, ignore specifiers after the _
            "indexed_file_location": protocol.split("_")[0],
            # pass URL for use with underlying indexed file location
            "url": None,
        }

    yield output

    mocker.unmock_functions()


@pytest.fixture(scope="function")
def indexd_client_with_arborist(app, request):
    record = {}
    mocker = Mocker()
    protocol = "s3"
    if hasattr(request, "param"):
        protocol = request.param

    def do_patch(authz):
        if protocol == "gs":
            record = {
                "did": "",
                "baseid": "",
                "rev": "",
                "size": 10,
                "file_name": "file1",
                "urls": ["gs://bucket1/key"],
                "authz": authz,
                "hashes": {},
                "metadata": {"acls": "phs000178,phs000218"},
                "form": "",
                "created_date": "",
                "updated_date": "",
            }
        elif protocol == "gs_acl":
            record = {
                "did": "",
                "baseid": "",
                "rev": "",
                "size": 10,
                "file_name": "file1",
                "urls": ["gs://bucket1/key"],
                "hashes": {},
                "acl": ["phs000178", "phs000218"],
                "authz": authz,
                "form": "",
                "created_date": "",
                "updated_date": "",
            }
        elif protocol == "s3_acl":
            record = {
                "did": "",
                "baseid": "",
                "rev": "",
                "size": 10,
                "file_name": "file1",
                "urls": ["s3://bucket1/key"],
                "hashes": {},
                "acl": ["phs000178", "phs000218"],
                "authz": authz,
                "form": "",
                "created_date": "",
                "updated_date": "",
            }
        elif protocol == "s3_external":
            record = {
                "did": "",
                "baseid": "",
                "rev": "",
                "size": 10,
                "file_name": "file1",
                "urls": ["s3://bucket1/key"],
                "hashes": {},
                "acl": ["phs000178", "phs000218"],
                "authz": authz,
                "form": "",
                "created_date": "",
                "updated_date": "",
            }
        elif protocol == "s3_and_gs":
            record = {
                "did": "",
                "baseid": "",
                "rev": "",
                "size": 10,
                "file_name": "file1",
                "urls": ["s3://bucket1/key", "gs://bucket1/key"],
                "authz": authz,
                "hashes": {},
                "metadata": {"acls": "phs000178,phs000218"},
                "form": "",
                "created_date": "",
                "updated_date": "",
            }
        elif protocol == "s3_and_gs_acl_no_authz":
            record = {
                "did": "",
                "baseid": "",
                "rev": "",
                "size": 10,
                "file_name": "file1",
                "urls": ["s3://bucket1/key", "gs://bucket1/key"],
                "authz": [],
                "hashes": {},
                "acl": ["phs000178", "phs000218"],
                "metadata": {"acls": "phs000178,phs000218"},
                "form": "",
                "created_date": "",
                "updated_date": "",
            }
        else:
            record = {
                "did": "",
                "baseid": "",
                "rev": "",
                "size": 10,
                "file_name": "file1",
                "urls": ["s3://bucket1/key"],
                "hashes": {},
                "metadata": {"acls": "phs000178,phs000218"},
                "authz": authz,
                "form": "",
                "created_date": "",
                "updated_date": "",
            }

        mocker.mock_functions()

        # TODO (rudyardrichter, 2018-11-03): consolidate things needing to do this patch
        indexd_patcher = patch(
            "fence.blueprints.data.indexd.IndexedFile.index_document", record
        )
        mocker.add_mock(indexd_patcher)

        output = {
            "mocker": mocker,
            # only gs or s3 for location, ignore specifiers after the _
            "indexed_file_location": protocol.split("_")[0],
        }

        return output

    yield do_patch

    mocker.unmock_functions()


@pytest.fixture(scope="function")
def indexd_client_accepting_record():
    """
    Patches IndexedFile's index_document with a caller-supplied dictionary
    representing an Indexd record.
    """

    mocker = Mocker()

    def do_patch(record):
        mocker.mock_functions()

        indexd_patcher = patch(
            "fence.blueprints.data.indexd.IndexedFile.index_document", record
        )
        mocker.add_mock(indexd_patcher)

    yield do_patch

    mocker.unmock_functions()


@pytest.fixture(scope="function")
def unauthorized_indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()
    record = {}

    protocol = "s3"
    if hasattr(request, "param"):
        protocol = request.param

    if protocol == "gs":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["gs://bucket5/key"],
            "hashes": {},
            "metadata": {"acls": "phs000178,phs000218"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "gs_acl":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["gs://bucket5/key"],
            "hashes": {},
            "acl": ["phs000178", "phs000218"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "s3_acl":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket5/key"],
            "hashes": {},
            "acl": ["phs000178", "phs000218"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    else:
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket5/key"],
            "hashes": {},
            "metadata": {"acls": "phs000178,phs000218"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }

    indexd_patcher = patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", record
    )
    mocker.add_mock(indexd_patcher)

    yield

    mocker.unmock_functions()


@pytest.fixture(scope="function")
def public_indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()

    protocol = "s3"
    if hasattr(request, "param"):
        protocol = request.param

    if protocol == "gs":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["gs://bucket1/key"],
            "hashes": {},
            "metadata": {"acls": "*"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "gs_acl":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["gs://bucket1/key"],
            "hashes": {},
            "acl": ["*"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "s3_acl":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket1/key"],
            "hashes": {},
            "acl": ["*"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    else:
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket1/key"],
            "hashes": {},
            "metadata": {"acls": "*"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }

    indexd_patcher = patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", record
    )
    mocker.add_mock(indexd_patcher)

    yield

    mocker.unmock_functions()


@pytest.fixture(scope="session")
def uploader_username():
    return "test-uploader"


@pytest.fixture(scope="function")
def public_bucket_indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()

    protocol = "s3"
    if hasattr(request, "param"):
        protocol = request.param

    if protocol == "gs":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["gs://bucket4/key"],
            "hashes": {},
            "metadata": {"acls": "*"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "gs_acl":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["gs://bucket4/key"],
            "hashes": {},
            "acl": ["*"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "s3_acl":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket4/key"],
            "hashes": {},
            "acl": ["*"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif protocol == "s2":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s2://bucket1/key"],
            "hashes": {},
            "metadata": {"acls": "*"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    elif request.param == "az":
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file2",
            # index the file as "az://fakeaccount.blob.core.windows.net/container5/blob6"
            # as fence should convert to "https://fakeaccount.blob.core.windows.net/container5/blob6"
            "urls": ["az://fakeaccount.blob.core.windows.net/container5/blob6"],
            "hashes": {},
            "acl": ["*"],
            "form": "",
            "created_date": "",
            "updated_date": "",
        }
    else:
        record = {
            "did": "",
            "baseid": "",
            "rev": "",
            "size": 10,
            "file_name": "file1",
            "urls": ["s3://bucket4/key"],
            "hashes": {},
            "metadata": {"acls": "*"},
            "form": "",
            "created_date": "",
            "updated_date": "",
        }

    indexd_patcher = patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", record
    )

    mock_blob_client_patcher = patch(
        "fence.blueprints.data.indexd.BlobServiceClient",
        return_value=FakeBlobServiceClient(),
    )
    mock_generate_blob_sas_patcher = patch(
        "fence.blueprints.data.indexd.generate_blob_sas",
        return_value="FAKE_SharedAccessSignature_STRING",
    )

    mocker.add_mock(indexd_patcher)
    mocker.add_mock(mock_blob_client_patcher)
    mocker.add_mock(mock_generate_blob_sas_patcher)

    yield protocol

    mocker.unmock_functions()


@pytest.fixture(scope="function")
def patch_app_db_session(app, monkeypatch):
    """
    TODO
    """

    def do_patch(session):
        monkeypatch.setattr(app.db, "Session", lambda: session)
        modules_to_patch = [
            "fence.auth",
            "fence.resources.google.utils",
            "fence.blueprints.admin",
            "fence.blueprints.link",
            "fence.blueprints.google",
            "fence.oidc.jwt_generator",
            "fence.user",
            "fence.blueprints.login.synapse",
            "fence.blueprints.login.ras",
        ]
        for module in modules_to_patch:
            monkeypatch.setattr("{}.current_session".format(module), session)

    return do_patch


@pytest.fixture(scope="function")
def oauth_client(app, db_session, oauth_user, get_all_shib_idps_patcher):
    """
    Create a confidential OAuth2 client and add it to the database along with a
    test user for the client.
    """
    url = "https://oauth-test-client.net"
    client_id = "test-client"
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(
        client_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    test_user = db_session.query(models.User).filter_by(id=oauth_user.user_id).first()
    db_session.add(
        models.Client(
            client_id=client_id,
            client_secret=hashed_secret,
            user=test_user,
            allowed_scopes=["openid", "user", "fence"],
            redirect_uris=[url],
            description="",
            is_confidential=True,
            name="testclient",
            grant_types=["authorization_code", "refresh_token"],
        )
    )
    db_session.commit()
    return Dict(client_id=client_id, client_secret=client_secret, url=url)


@pytest.fixture(scope="function")
def oauth_client_B(app, request, db_session):
    """
    Create a second, different OAuth2 (confidential) client and add it to the
    database along with a test user for the client.
    """
    url = "https://oauth-test-client-B.net"
    client_id = "test-client-B"
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(
        client_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    test_user = db_session.query(models.User).filter_by(username="test").first()
    if not test_user:
        test_user = models.User(username="test", is_admin=False)
        db_session.add(test_user)
    db_session.add(
        models.Client(
            client_id=client_id,
            client_secret=hashed_secret,
            user=test_user,
            allowed_scopes=["openid", "user", "fence"],
            redirect_uris=[url],
            description="",
            is_confidential=True,
            name="testclientb",
            grant_types=["authorization_code", "refresh_token"],
        )
    )
    db_session.commit()

    return Dict(client_id=client_id, client_secret=client_secret, url=url)


@pytest.fixture(scope="function")
def oauth_client_public(app, db_session, oauth_user):
    """
    Create a public OAuth2 client.
    """
    url = "https://oauth-test-client-public.net"
    client_id = "test-client-public"
    test_user = db_session.query(models.User).filter_by(id=oauth_user.user_id).first()
    db_session.add(
        models.Client(
            client_id=client_id,
            user=test_user,
            allowed_scopes=["openid", "user", "fence"],
            redirect_uris=[url],
            description="",
            is_confidential=False,
            name="testclient-public",
            grant_types=["authorization_code", "refresh_token"],
        )
    )
    db_session.commit()
    return Dict(client_id=client_id, url=url)


@pytest.fixture(scope="function")
def oauth_test_client(client, oauth_client):
    return OAuth2TestClient(client, oauth_client, confidential=True)


@pytest.fixture(scope="function")
def oauth_test_client_B(client, oauth_client_B):
    return OAuth2TestClient(client, oauth_client_B, confidential=True)


@pytest.fixture(scope="function")
def oauth_test_client_public(client, oauth_client_public):
    return OAuth2TestClient(client, oauth_client_public, confidential=False)


@pytest.fixture(scope="session")
def microsoft_oauth2_client():
    settings = MagicMock()
    settings.get.return_value = None
    logger = MagicMock()
    client = MicrosoftOauth2Client(settings=settings, logger=logger)

    return client


@pytest.fixture(scope="function")
def primary_google_service_account(app, db_session, user_client, google_proxy_group):
    service_account_id = "test-service-account-0"
    email = fence.utils.random_str(40) + "@test.com"
    service_account = models.GoogleServiceAccount(
        google_unique_id=service_account_id,
        email=email,
        user_id=user_client.user_id,
        client_id=None,
        google_project_id="projectId-0",
    )
    db_session.add(service_account)
    db_session.commit()

    mock = MagicMock()
    mock.return_value = service_account
    patcher = patch("fence.resources.google.utils.get_or_create_service_account", mock)
    patcher.start()

    yield Dict(
        id=service_account_id, email=email, get_or_create_service_account_mock=mock
    )

    patcher.stop()


@pytest.fixture(scope="function")
def primary_google_service_account_google(
    app, db_session, user_client, google_proxy_group
):
    service_account_id = "test-service-account-0"
    email = fence.utils.random_str(40) + "@test.com"
    service_account = models.GoogleServiceAccount(
        google_unique_id=service_account_id,
        email=email,
        user_id=user_client.user_id,
        client_id=None,
        google_project_id="projectId-0",
    )
    db_session.add(service_account)
    db_session.commit()

    service_account_key_db_entry = models.GoogleServiceAccountKey(
        key_id=1, service_account_id=service_account.id, expires=int(time.time()) + 3600
    )

    db_session.add(service_account_key_db_entry)
    db_session.commit()

    private_key = {
        "type": "service_account",
        "project_id": "project-id",
        "private_key_id": "some_number",
        "client_email": email,
        "client_id": "...",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com",
    }

    mock = MagicMock()
    mock.return_value = private_key, service_account_key_db_entry
    patcher = patch(
        "fence.blueprints.google.get_or_create_primary_service_account_key", mock
    )
    patcher.start()

    yield Dict(
        id=service_account_id, email=email, get_or_create_service_account_mock=mock
    )

    db_session.delete(service_account)
    db_session.delete(service_account_key_db_entry)
    db_session.commit()

    patcher.stop()


@pytest.fixture(scope="function")
def google_proxy_group(app, db_session, user_client):
    group_id = "test-proxy-group-0"
    email = fence.utils.random_str(40) + "@test.com"
    test_user = db_session.query(models.User).filter_by(id=user_client.user_id).first()
    test_user.google_proxy_group_id = group_id
    db_session.add(models.GoogleProxyGroup(id=group_id, email=email))
    db_session.commit()
    return Dict(id=group_id, email=email)


@pytest.fixture(scope="function")
def cloud_manager():
    manager = MagicMock()
    patch("fence.blueprints.storage_creds.google.GoogleCloudManager", manager).start()
    patch("fence.resources.google.utils.GoogleCloudManager", manager).start()
    patch("fence.scripting.fence_create.GoogleCloudManager", manager).start()
    patch("fence.scripting.google_monitor.GoogleCloudManager", manager).start()
    patch("fence.resources.admin.admin_users.GoogleCloudManager", manager).start()
    patch("fence.resources.google.access_utils.GoogleCloudManager", manager).start()
    patch("fence.resources.google.validity.GoogleCloudManager", manager).start()
    patch("fence.blueprints.google.GoogleCloudManager", manager).start()
    manager.return_value.__enter__.return_value.get_access_key.return_value = {
        "type": "service_account",
        "project_id": "project-id",
        "private_key_id": "some_number",
        "private_key": "-----BEGIN PRIVATE KEY-----\n....\n-----END PRIVATE KEY-----\n",
        "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
        "client_id": "...",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com",
    }
    return manager


@pytest.fixture(scope="function")
def google_signed_url():
    manager = MagicMock()
    patch(
        "fence.blueprints.data.indexd.cirrus.google_cloud.utils.get_signed_url", manager
    ).start()

    # Note: example outpu/format from google's docs, will not actually work
    manager.return_value = (
        "https://storage.googleapis.com/google-testbucket/testdata.txt?GoogleAccessId="
        "1234567890123@developer.gserviceaccount.com&Expires=1331155464&Signature=BCl"
        "z9e4UA2MRRDX62TPd8sNpUCxVsqUDG3YGPWvPcwN%2BmWBPqwgUYcOSszCPlgWREeF7oPGowkeKk"
        "7J4WApzkzxERdOQmAdrvshKSzUHg8Jqp1lw9tbiJfE2ExdOOIoJVmGLoDeAGnfzCd4fTsWcLbal9"
        "sFpqXsQI8IQi1493mw%3D"
    )
    return manager


@pytest.fixture(scope="function")
def encoded_creds_jwt(
    kid, rsa_private_key, user_client, oauth_client, google_proxy_group
):
    """
    Return a JWT and user_id for a new user containing the claims and
    encoded with the private key.
    Args:
        claims (dict): fixture
        rsa_private_key (str): fixture
    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {"kid": kid}
    return Dict(
        jwt=jwt.encode(
            utils.authorized_download_credentials_context_claims(
                user_client["username"],
                user_client["user_id"],
                oauth_client["client_id"],
                google_proxy_group["id"],
            ),
            key=rsa_private_key,
            headers=headers,
            algorithm="RS256",
        ).decode("utf-8"),
        user_id=user_client["user_id"],
        client_id=oauth_client["client_id"],
        proxy_group_id=google_proxy_group["id"],
        username=user_client["username"],
    )


@pytest.fixture(scope="function")
def encoded_jwt_no_proxy_group(kid, rsa_private_key, user_client, oauth_client):
    """
    Return a JWT and user_id for a new user containing the claims and
    encoded with the private key.
    Args:
        claims (dict): fixture
        rsa_private_key (str): fixture
    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {"kid": kid}
    return Dict(
        jwt=jwt.encode(
            utils.authorized_download_credentials_context_claims(
                user_client["username"],
                user_client["user_id"],
                oauth_client["client_id"],
            ),
            key=rsa_private_key,
            headers=headers,
            algorithm="RS256",
        ).decode("utf-8"),
        user_id=user_client["user_id"],
        client_id=oauth_client["client_id"],
    )


@pytest.fixture(scope="function")
def user_with_fence_provider(app, request, db_session):
    """
    Create a second, different OAuth2 (confidential) client and add it to the
    database along with a test user for the client.
    """
    fence_provider = (
        db_session.query(models.IdentityProvider).filter_by(name="fence").first()
    )
    if not fence_provider:
        fence_provider = models.IdentityProvider(name="fence")
        db_session.add(fence_provider)
        db_session.commit()

    test_user = (
        db_session.query(models.User).filter_by(username="test-fence-provider").first()
    )
    if test_user:
        test_user.idp_id = fence_provider.id
    else:
        test_user = models.User(
            username="test-fence-provider", is_admin=False, idp_id=fence_provider.id
        )
        db_session.add(test_user)

    db_session.commit()

    return test_user


@pytest.fixture(scope="function")
def google_storage_client_mocker(app):
    storage_client_mock = MagicMock()

    temp = app.storage_manager
    app.storage_manager.clients["google"] = storage_client_mock

    yield storage_client_mock

    app.storage_manager = temp


@pytest.fixture(scope="function")
def restore_config():
    """
    Restore original config at teardown.
    """
    saved_config = copy.deepcopy(config._configs)

    yield

    # restore old configs
    config.update(saved_config)


@pytest.fixture(scope="function")
def get_all_shib_idps_patcher():
    """
    Don't make real requests to the list of InCommon IDPs exposed
    by login.bionimbus
    """
    mock = MagicMock()
    mock.return_value = [
        {
            "idp": "some-incommon-entity-id",
            "name": "Some InCommon Provider",
        },
        {
            "idp": "urn:mace:incommon:nih.gov",
            "name": "National Institutes of Health (NIH)",
        },
        {
            "idp": "urn:mace:incommon:uchicago.edu",
            "name": "University of Chicago",
        },
    ]
    get_all_shib_idps_patch = patch(
        "fence.blueprints.login.get_all_shib_idps",
        mock,
    )
    get_all_shib_idps_patch.start()

    yield mock

    get_all_shib_idps_patch.stop()
