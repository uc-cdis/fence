from datetime import datetime, timedelta
import os
import uuid

from addict import Dict
import jwt
import pytest
from userdatamodel import Base

from . import test_settings
import fence
from fence import models


def check_auth_positive(cls, backend, user):
    return True


@pytest.fixture(scope='function')
def app(request):
    fence.app_init(fence.app, test_settings)
    yield fence.app
    for tbl in reversed(Base.metadata.sorted_tables):
        fence.app.db.engine.execute(tbl.delete())


@pytest.fixture(scope='session')
def iss():
    """
    Return the token issuer.
    """
    return 'https://user-api.test.net'


@pytest.fixture(scope='session')
def aud():
    """
    Return some default audiences to put in the claims of a JWT.
    """
    return ['access', 'user']


@pytest.fixture(scope='session')
def jti():
    """
    Return a JWT identifier (``jti``).
    """
    return str(uuid.uuid4())


@pytest.fixture(scope='session')
def iat_and_exp():
    """
    Return ``iat`` and ``exp`` claims for a JWT.
    """
    now = datetime.now()
    iat = int(now.strftime('%s'))
    exp = int((now + timedelta(seconds=60)).strftime('%s'))
    return (iat, exp)


@pytest.fixture(scope='session')
def claims(aud, iat_and_exp, iss, jti):
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    iat, exp = iat_and_exp
    return {
        'aud': aud,
        'sub': '1234',
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': 'test-user',
                'projects': [
                ],
            },
        },
    }


@pytest.fixture(scope='session')
def claims_refresh(claims):
    new_claims = claims.copy()
    new_claims['aud'] = ['refresh']
    return new_claims


@pytest.fixture(scope='session')
def public_key():
    """
    Return a public key for testing.
    """
    os.path.dirname(os.path.realpath(__file__))
    here = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(here, 'keys/test_public_key.pem')) as f:
        return f.read()


@pytest.fixture(scope='session')
def private_key():
    """
    Return a private key for testing. (Use only a private key that is
    specifically set aside for testing, and never actually used for auth.)
    """
    os.path.dirname(os.path.realpath(__file__))
    here = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(here, 'keys/test_private_key.pem')) as f:
        return f.read()


@pytest.fixture(scope='session')
def encoded_jwt(claims, private_key):
    """
    Return an example JWT containing the claims and encoded with the private
    key.

    Args:
        claims (dict): fixture
        private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    return jwt.encode(claims, key=private_key, algorithm='RS256')


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
    return jwt.encode(claims_refresh, key=private_key, algorithm='RS256')


@pytest.fixture()
def oauth_client(app, request):
    url = 'https://test.com'
    client_id, client_secret = fence.utils.create_client(
        username='test', urls=url, DB=app.config['DB']
    )

    def fin():
        with app.db.session as s:
            all_models = [
                models.BlacklistedToken,
                models.Client,
                models.Grant,
                models.Token,
                models.User,
            ]
            for cls in all_models:
                for obj in s.query(cls).all():
                    s.delete(obj)

    request.addfinalizer(fin)
    return Dict(client_id=client_id, client_secret=client_secret, url=url)
