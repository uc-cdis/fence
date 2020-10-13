import jwt
import pytest


@pytest.fixture(scope="session")
def encoded_jwt(kid, rsa_private_key):
    """
    Return an example JWT containing the claims and encoded with the private
    key.

    Args:
        kid (str): fixture
        rsa_private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {"kid": kid}
    return jwt.encode(
        utils.default_claims(), key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")


@pytest.fixture(scope="session")
def encoded_jwt_expired(claims, kid, rsa_private_key):
    """
    Return an example JWT that has already expired.

    Args:
        claims (dict): fixture
        kid (str): fixture
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
        kid (str): fixture
        rsa_private_key (str): fixture

    Return:
        str: JWT refresh token containing claims encoded with private key
    """
    headers = {"kid": kid}
    return jwt.encode(
        claims_refresh, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")
