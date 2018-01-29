# pylint: disable=redefined-outer-name
"""
Define pytest fixtures.
"""

from mock import patch
import os

from addict import Dict
import bcrypt
from cdisutilstest.code.storage_client_mock import get_client
import flask_sqlalchemy_session
import jwt
import pytest

import fence
from fence import app_init
from fence import models

import tests
from tests import test_settings, utils


# Allow authlib to use HTTP for local testing.
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


@pytest.fixture(scope='session')
def claims_refresh():
    new_claims = tests.utils.default_claims()
    new_claims['aud'] = ['refresh']
    return new_claims


@pytest.fixture(scope='session')
def public_key():
    """
    Return a public key for testing.
    """
    return utils.read_file('keys/test_public_key.pem')


@pytest.fixture(scope='session')
def private_key():
    """
    Return a private key for testing. (Use only a private key that is
    specifically set aside for testing, and never actually used for auth.)
    """
    return utils.read_file('keys/test_private_key.pem')


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


@pytest.fixture(scope='session')
def app():
    mocker = Mocker()
    mocker.mock_functions()
    root_dir = os.path.dirname(os.path.realpath(__file__))
    app_init(fence.app, test_settings, root_dir=root_dir)
    return fence.app


@fence.app.route('/protected')
@fence.auth.login_required({'access'})
def protected_endpoint(methods=['GET']):
    """
    Add a protected endpoint to the app for testing.
    """
    return 'Got to protected endpoint'


def check_auth_positive(cls, backend, user):
    return True


class Mocker(object):
    def mock_functions(self):
        self.patcher = patch(
            'fence.resources.storage.get_client',
            get_client
        )
        self.auth_patcher = patch(
            'fence.resources.storage.StorageManager.check_auth',
            check_auth_positive)
        self.auth_patcher.start()
        self.patcher.start()

    def unmock_functions(self):
        self.patcher.stop()
        self.auth_patcher.stop()


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


@pytest.fixture(scope='function')
def db_session(db, request, patch_app_db_session, monkeypatch):
    """
    Define fixture for database session (function-scoped).

    At the end of the function, roll back the session to its initial state.
    """
    connection = db.engine.connect()
    transaction = connection.begin()
    session = db.Session(bind=connection)

    def rollback():
        """
        After using the session, roll back any changes made (including
        commits.
        """
        session.close()
        transaction.rollback()
        connection.close()

    request.addfinalizer(rollback)

    patch_app_db_session(session)

    return session


@pytest.fixture(scope='function')
def patch_app_db_session(app, monkeypatch):
    """
    TODO
    """

    def do_patch(session):
        monkeypatch.setattr(app.db, 'Session', lambda: session)
        monkeypatch.setattr('fence.auth.current_session', session)
        monkeypatch.setattr('fence.user.current_session', session)

    return do_patch


@pytest.fixture(scope='function')
def oauth_client(app, request, db_session):
    url = 'https://oauth-test-client.net'
    client_id = 'test-client'
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())
    test_user = models.User(username='test', is_admin=False)

    db_session.add(test_user)
    db_session.add(models.Client(
        client_id=client_id, client_secret=hashed_secret, user=test_user,
        allowed_scopes=['openid', 'user'], _redirect_uris=url, description=''
    ))
    db_session.commit()

    return Dict(client_id=client_id, client_secret=client_secret, url=url)
