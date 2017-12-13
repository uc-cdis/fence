import fence
import jwt
import pytest
import uuid

from addict import Dict
from datetime import datetime, timedelta
from mock import patch

from cdisutilstest.code.storage_client_mock import StorageClientMocker, get_client
from fence.jwt import blacklist
from fence.data_model import models
from fence import app_init
from userdatamodel import Base

from tests import test_settings
from tests import utils


def check_auth_positive(cls, backend, user):
    return True


@pytest.fixture(scope='session')
def claims_refresh():
    new_claims = utils.default_claims()
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


class Mocker(object):
    def mock_functions(self):
        self.patcher = patch(
            'fence.resources.storage.get_client',
            get_client)
        self.auth_patcher = patch(
            'fence.resources.storage.StorageManager.check_auth',
            check_auth_positive)
        self.auth_patcher.start()
        self.patcher.start()

    def unmock_functions(self):
        self.patcher.stop()
        self.auth_patcher.stop()


@pytest.fixture(scope='function')
def app(request):
    mocker = Mocker()
    mocker.mock_functions()
    app_init(fence.app, test_settings)

    def fin():
        for tbl in reversed(Base.metadata.sorted_tables):
            fence.app.db.engine.execute(tbl.delete())
        mocker.unmock_functions()
    request.addfinalizer(fin)
    return fence.app


@pytest.fixture(scope='function')
def oauth_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()
    url = 'https://test.net'
    client_id, client_secret = fence.utils.create_client(
        username='test', urls=url, DB=app.config['DB']
    )
    # yield Dict(client_id=client_id, client_secret=client_secret, url=url)

    def fin():
        with app.db.session as session:
            # Don't flush until everything is finished, otherwise this will break
            # because of (for example) foreign key references between the tables.
            with session.no_autoflush:
                all_models = [
                    blacklist.BlacklistedToken,
                    models.Client,
                    models.Grant,
                    models.Token,
                    models.User,
                ]
                for cls in all_models:
                    for obj in session.query(cls).all():
                        session.delete(obj)

    request.addfinalizer(fin)
    return Dict(client_id=client_id, client_secret=client_secret, url=url)
