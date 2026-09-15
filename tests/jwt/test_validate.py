"""
Test fence's JWT validation wrapper.
"""

import authutils.token.keys
import jwt
import pytest

from fence.config import config
from fence.jwt.errors import JWTError
from fence.jwt.validate import validate_jwt
from tests.utils import default_claims

UNKNOWN_ISSUER = "https://not-an-allowed-issuer.example.com"


@pytest.fixture
def discovery_attempts(monkeypatch):
    """
    Record every public key lookup instead of performing one.

    Lookups resolve a JWKS URL from the token's unverified `iss` and fetch it, so
    "was this called" is the observable stand-in for "did fence make an outbound
    request on behalf of an unvalidated token".

    Return:
        list[str]: encoded tokens that key discovery was attempted for
    """
    attempts = []

    def record(encoded_token, **kwargs):
        attempts.append(encoded_token)
        raise _DiscoveryAttempted()

    monkeypatch.setattr(
        authutils.token.keys, "get_public_key_for_token", record, raising=True
    )
    return attempts


class _DiscoveryAttempted(Exception):
    """Marks that key discovery was reached, so the test can stop there."""


def encode_token(claims, kid, rsa_private_key):
    """
    Encode claims as an RS256 JWT.

    Args:
        claims (dict): claims to encode
        kid (str): key id to put in the token header
        rsa_private_key (str): private key to sign with

    Return:
        str: the encoded token
    """
    return jwt.encode(
        claims, key=rsa_private_key, headers={"kid": kid}, algorithm="RS256"
    )


@pytest.mark.parametrize(
    ("token_issuer", "allowed_issuers"),
    [
        (UNKNOWN_ISSUER, [config["BASE_URL"]]),
        (config["BASE_URL"], []),
    ],
    ids=["issuer_not_allowed", "empty_allowlist"],
)
def test_issuer_no_allowlist_admits_is_rejected_before_key_discovery(
    kid, rsa_private_key, discovery_attempts, token_issuer, allowed_issuers
):
    """A token whose issuer the allowlist does not admit is rejected without a lookup."""
    claims = default_claims()
    claims["iss"] = token_issuer
    token = encode_token(claims, kid, rsa_private_key)

    with pytest.raises(JWTError):
        validate_jwt(token, issuers=allowed_issuers, scope=None)

    assert discovery_attempts == []


def test_allowed_issuer_reaches_key_discovery(kid, rsa_private_key, discovery_attempts):
    """A token from an allowed issuer is still looked up as before."""
    token = encode_token(default_claims(), kid, rsa_private_key)

    with pytest.raises(_DiscoveryAttempted):
        validate_jwt(token, issuers=[config["BASE_URL"]], scope=None)

    assert discovery_attempts == [token]


def test_supplied_public_key_skips_key_discovery(
    kid, rsa_private_key, rsa_public_key, discovery_attempts
):
    """A caller-supplied public key means no lookup happens at all."""
    claims = default_claims()
    claims["iss"] = UNKNOWN_ISSUER
    token = encode_token(claims, kid, rsa_private_key)

    with pytest.raises(JWTError):
        validate_jwt(
            token, issuers=[config["BASE_URL"]], scope=None, public_key=rsa_public_key
        )

    assert discovery_attempts == []
