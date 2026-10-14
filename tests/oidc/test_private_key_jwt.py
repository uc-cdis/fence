"""
Tests for fence.oidc.private_key_jwt (FencePrivateKeyJWT).

Covers create_claims_options() and resolve_client_public_key() for all key
lookup branches: no JWKS, matching kid, kid not found, no kid, empty key set.
"""

import pytest
from unittest.mock import MagicMock

from authlib.jose import JsonWebKey
from authlib.oauth2.rfc6749 import InvalidClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fence.config import config
from fence.oidc.private_key_jwt import FencePrivateKeyJWT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_rsa_jwks(kid=None):
    """Return (private_key, jwks_dict) with an optionally-tagged public JWK."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk_obj = JsonWebKey.import_key(pub_pem)
    jwk_dict = dict(jwk_obj)
    if kid:
        jwk_dict["kid"] = kid
    return private_key, {"keys": [jwk_dict]}


def _client_with_jwks(jwks_value):
    """Return a mock Client whose .jwks attribute returns jwks_value."""
    client = MagicMock()
    type(client).jwks = property(lambda self: jwks_value)
    return client


# ---------------------------------------------------------------------------
# create_claims_options() tests
# ---------------------------------------------------------------------------


def test_create_claims_options_has_required_keys(app):
    """create_claims_options returns dict with iss, sub, aud, exp keys."""
    handler = FencePrivateKeyJWT()
    opts = handler.create_claims_options()
    assert "iss" in opts
    assert "sub" in opts
    assert "aud" in opts
    assert "exp" in opts


def test_create_claims_options_aud_value_is_token_endpoint(app):
    """aud.value must point to the /oauth2/token endpoint."""
    handler = FencePrivateKeyJWT()
    opts = handler.create_claims_options()
    expected = config["BASE_URL"].rstrip("/") + "/oauth2/token"
    assert opts["aud"]["value"] == expected


def test_create_claims_options_aud_is_essential(app):
    """aud is marked essential."""
    handler = FencePrivateKeyJWT()
    opts = handler.create_claims_options()
    assert opts["aud"].get("essential") is True


def test_create_claims_options_exp_is_essential(app):
    """exp is marked essential."""
    handler = FencePrivateKeyJWT()
    opts = handler.create_claims_options()
    assert opts["exp"].get("essential") is True


def test_create_claims_options_iss_validator_matches_sub(app):
    """iss validator accepts iss == sub."""
    handler = FencePrivateKeyJWT()
    validate = handler.create_claims_options()["iss"]["validate"]
    claims = {"iss": "client-id", "sub": "client-id"}
    assert validate(claims, "client-id") is True


def test_create_claims_options_iss_validator_rejects_iss_ne_sub(app):
    """iss validator rejects iss != sub (RFC 7523 §3)."""
    handler = FencePrivateKeyJWT()
    validate = handler.create_claims_options()["iss"]["validate"]
    claims = {"iss": "client-id", "sub": "other-id"}
    assert validate(claims, "client-id") is False


# ---------------------------------------------------------------------------
# resolve_client_public_key() tests
# ---------------------------------------------------------------------------


def test_resolve_public_key_no_jwks_raises(app):
    """Client with no registered JWKS raises InvalidClientError."""
    handler = FencePrivateKeyJWT()
    client = _client_with_jwks([])  # empty list → falsy
    with pytest.raises(InvalidClientError):
        handler.resolve_client_public_key(client, {})


def test_resolve_public_key_matching_kid_returns_key(app):
    """Returns the key when the kid in the JWT header matches one in JWKS."""
    _, jwks = _generate_rsa_jwks(kid="signing-key")
    handler = FencePrivateKeyJWT()
    client = _client_with_jwks(jwks)
    key = handler.resolve_client_public_key(client, {"kid": "signing-key"})
    assert key is not None


def test_resolve_public_key_unknown_kid_raises(app):
    """kid in header not found in JWKS raises InvalidClientError."""
    _, jwks = _generate_rsa_jwks(kid="signing-key")
    handler = FencePrivateKeyJWT()
    client = _client_with_jwks(jwks)
    with pytest.raises(InvalidClientError):
        handler.resolve_client_public_key(client, {"kid": "unknown-kid"})


def test_resolve_public_key_no_kid_returns_first_key(app):
    """No kid in header returns the first key from the JWKS."""
    _, jwks = _generate_rsa_jwks(kid="signing-key")
    handler = FencePrivateKeyJWT()
    client = _client_with_jwks(jwks)
    key = handler.resolve_client_public_key(client, {})
    assert key is not None


def test_resolve_public_key_empty_keys_array_raises(app):
    """JWKS dict with an empty keys array raises InvalidClientError."""
    handler = FencePrivateKeyJWT()
    client = _client_with_jwks({"keys": []})
    with pytest.raises(InvalidClientError):
        handler.resolve_client_public_key(client, {})
