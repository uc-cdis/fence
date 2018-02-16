import jwt
import pytest

from tests import test_settings, utils


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
