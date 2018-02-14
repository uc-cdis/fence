# pylint: disable=redefined-outer-name
"""
Define pytest fixtures.
"""

import json
import jwt
import mock
from mock import patch, MagicMock
import os

from addict import Dict
import bcrypt
from cdisutilstest.code.storage_client_mock import get_client
import pytest
import requests

import fence
from fence import app_init
from fence import models

import tests
from tests import test_settings
from tests import utils


# Allow authlib to use HTTP for local testing.
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


def indexd_get_available_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket1/key'],
        'hashes': {},
        'metadata': {'acls': 'phs000178,phs000218'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_unavailable_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket5/key'],
        'hashes': {},
        'metadata': {'acls': 'phs000178,phs000218'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


@pytest.fixture(scope='session')
def claims_refresh():
    new_claims = tests.utils.default_claims()
    new_claims['pur'] = 'refresh'
    new_claims['aud'].append('fence')
    return new_claims


@pytest.fixture(scope='session')
def public_key():
    """
    Return a public key for testing.
    """
    return utils.read_file('resources/keys/test_public_key.pem')


@pytest.fixture(scope='session')
def private_key():
    """
    Return a private key for testing. (Use only a private key that is
    specifically set aside for testing, and never actually used for auth.)
    """
    return utils.read_file('resources/keys/test_private_key.pem')


@pytest.fixture(scope='session')
def encoded_jwt(private_key):
    """
    Return an example JWT containing the claims and encoded with the private
    key.

    Args:
        claims (dict): fixture
        private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    headers = {'kid': kid}
    return jwt.encode(
        utils.default_claims(),
        key=private_key,
        headers=headers,
        algorithm='RS256',
    )


@pytest.fixture(scope='session')
def encoded_jwt_expired(claims, private_key):
    """
    Return an example JWT that has already expired.

    Args:
        claims (dict): fixture
        private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    headers = {'kid': kid}
    claims_expired = utils.default_claims()
    # Move `exp` and `iat` into the past.
    claims_expired['exp'] -= 10000
    claims_expired['iat'] -= 10000
    return jwt.encode(
        claims_expired, key=private_key, headers=headers, algorithm='RS256'
    )


@pytest.fixture(scope='session')
def encoded_jwt_refresh_token(claims_refresh, private_key):
    """
    Return an example JWT refresh token containing the claims and encoded with
    the private key.

    Args:
        claims_refresh (dict): fixture
        private_key (str): fixture

    Return:
        str: JWT refresh token containing claims encoded with private key
    """
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    headers = {'kid': kid}
    return jwt.encode(
        claims_refresh, key=private_key, headers=headers, algorithm='RS256'
    )


class Mocker(object):

    def mock_functions(self):
        self.patcher = patch(
            'fence.resources.storage.get_client',
            get_client
        )
        self.auth_patcher = patch(
            'fence.resources.storage.StorageManager.check_auth',
            lambda cls, backend, user: True
        )
        self.patcher.start()
        self.auth_patcher.start()
        self.additional_patchers = []

    def unmock_functions(self):
        self.patcher.stop()
        self.auth_patcher.stop()
        for patcher in self.additional_patchers:
            patcher.stop()

    def add_mock(self, patcher):
        patcher.start()
        self.additional_patchers.append(patcher)


@pytest.fixture(scope='session')
def app():
    """
    Flask application fixture.
    """
    mocker = Mocker()
    mocker.mock_functions()
    root_dir = os.path.dirname(os.path.realpath(__file__))
    app_init(fence.app, test_settings, root_dir=root_dir)
    return fence.app


@pytest.fixture(scope='session')
def db(app, request):
    """
    Define pytest fixture for database engine (session-scoped).

    When the tests are over, drop everything from the test database.
    """

    def drop_all():
        models.Base.metadata.drop_all(app.db.engine)

    request.addfinalizer(drop_all)

    return app.db


@fence.app.route('/protected')
@fence.auth.login_required({'access'})
def protected_endpoint(methods=['GET']):
    """
    Add a protected endpoint to the app for testing.
    """
    return 'Got to protected endpoint'


@pytest.fixture(scope='function')
def user_client(app, request, db_session):
    users = dict(json.loads(
        utils.read_file('resources/authorized_users.json')
    ))
    user_id, username = utils.create_user(users, db_session, is_admin=True)
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope='function')
def unauthorized_user_client(app, request, db_session):
    users = dict(json.loads(
        utils.read_file('resources/unauthorized_users.json')
    ))
    user_id, username = utils.create_user(users, db_session, is_admin=True)
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope='function')
def db_session(db, request, patch_app_db_session, monkeypatch):
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


@pytest.fixture(scope='function')
def oauth_user(app, db_session):
    users = dict(json.loads(utils.read_file(
        'resources/authorized_users.json'
    )))
    user_id, username = utils.create_user(
        users, db_session, is_admin=True
    )
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope='function')
def unauthorized_oauth_user(app, db_session):
    users = dict(json.loads(utils.read_file(
        'resources/unauthorized_users.json'
    )))
    user_id, username = utils.create_user(
        users, db_session, is_admin=True
    )
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope='function')
def indexd_client(app):
    mocker = Mocker()
    mocker.mock_functions()
    indexd_patcher = patch(
        'fence.blueprints.data.get_index_document',
        indexd_get_available_bucket
    )
    mocker.add_mock(indexd_patcher)


@pytest.fixture(scope='function')
def unauthorized_indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()
    indexd_patcher = patch(
        'fence.blueprints.data.get_index_document',
        indexd_get_unavailable_bucket)
    mocker.add_mock(indexd_patcher)


@pytest.fixture(scope='function')
def patch_app_db_session(app, monkeypatch):
    """
    TODO
    """

    def do_patch(session):
        monkeypatch.setattr(app.db, 'Session', lambda: session)
        modules_to_patch = [
            'fence.auth',
            'fence.blueprints.storage_creds',
            'fence.oidc.jwt_generator',
            'fence.user',
        ]
        for module in modules_to_patch:
            monkeypatch.setattr('{}.current_session'.format(module), session)

    return do_patch


@pytest.fixture(scope='function')
def oauth_client(app, db_session, oauth_user):
    """
    Create a confidential OAuth2 client and add it to the database along with a
    test user for the client.
    """
    url = 'https://oauth-test-client.net'
    client_id = 'test-client'
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())
    test_user = (
        db_session
        .query(models.User)
        .filter_by(id=oauth_user.user_id)
        .first()
    )
    db_session.add(models.Client(
        client_id=client_id, client_secret=hashed_secret, user=test_user,
        allowed_scopes=['openid', 'user'], _redirect_uris=url, description='',
        is_confidential=True, name='testclient'
    ))
    db_session.commit()
    return Dict(client_id=client_id, client_secret=client_secret, url=url)


@pytest.fixture(scope='function')
def oauth_client_B(app, request, db_session):
    """
    Create a second, different OAuth2 client and add it to the database along
    with a test user for the client.
    """
    url = 'https://oauth-test-client-B.net'
    client_id = 'test-client-B'
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())

    test_user = (
        db_session
        .query(models.User)
        .filter_by(username='test')
        .first()
    )
    if not test_user:
        test_user = models.User(username='test', is_admin=False)
        db_session.add(test_user)
    db_session.add(models.Client(
        client_id=client_id, client_secret=hashed_secret, user=test_user,
        allowed_scopes=['openid', 'user'], _redirect_uris=url, description='',
        is_confidential=True, name='testclientb'
    ))
    db_session.commit()

    return Dict(client_id=client_id, client_secret=client_secret, url=url)


@pytest.fixture(scope='function')
def cloud_manager():
    manager = MagicMock()
    patch('fence.blueprints.storage_creds.GoogleCloudManager', manager).start()
    return manager


@pytest.fixture(scope='function')
def mock_get(monkeypatch, example_keys_response):
    """
    Provide a function to patch the value of the JSON returned by
    ``requests.get``.

    Args:
        monkeypatch (pytest.monkeypatch.MonkeyPatch): fixture

    Return:
        Calllable[dict, None]:
            function which sets the reponse JSON of ``requests.get``
    """

    def do_patch(urls_to_responses=None):
        """
        Args:
            keys_response_json (dict): value to set /jwt/keys return value to

        Return:
            None

        Side Effects:
            Patch ``requests.get``
        """

        def get(url):
            """Define a mock ``get`` function to return a mocked response."""
            mocked_response = mock.MagicMock(requests.Response)
            mocked_response.json.return_value = urls_to_responses[url]
            return mocked_response

        monkeypatch.setattr('requests.get', mock.MagicMock(side_effect=get))

    return do_patch
