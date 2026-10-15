import jwt as pyjwt
import pytest

from fence.config import config
from fence.jwt.blacklist import (
    blacklist_encoded_token,
    blacklist_token,
    is_blacklisted,
    is_token_blacklisted,
)

from tests import utils


def _encode_refresh_token(keypair):
    """Sign a revocable refresh token with a specific keypair."""
    iat, exp = utils.iat_and_exp()
    jti = utils.new_jti()
    claims = {
        "pur": "refresh",
        "aud": "openid",
        "scope": ["openid", "user"],
        "sub": "1",
        "iss": config["BASE_URL"],
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": "",
        "context": {"user": {"name": "test"}},
    }
    encoded_token = pyjwt.encode(
        claims,
        keypair.private_key,
        algorithm="RS256",
        headers={"kid": keypair.kid},
    )
    return encoded_token, jti, exp


def test_jti_not_blacklisted(app):
    """
    Test checking a ``jti`` which has not been blacklisted.
    """
    assert not is_blacklisted(utils.new_jti())


def test_blacklist(app):
    """
    Test blacklisting a ``jti`` directly.
    """
    _, exp = utils.iat_and_exp()
    jti = utils.new_jti()
    blacklist_token(jti, exp)
    assert is_blacklisted(jti)


def test_normal_token_not_blacklisted(app, encoded_jwt_refresh_token):
    """
    Test that a (refresh) token which was not blacklisted returns not
    blacklisted.
    """
    _, is_blacklisted = is_token_blacklisted(encoded_jwt_refresh_token)
    assert not is_blacklisted


@pytest.mark.parametrize("keypair_index", [0, 1])
def test_token_from_any_loaded_keypair_can_be_revoked(app, db_session, keypair_index):
    """
    Revoking a token signed by any loaded keypair records it on the denylist.

    Every loaded keypair is published in the JWKS and accepted at validation, so
    revocation has to cover the non-current ones too: otherwise a routine key rotation
    silently leaves every outstanding token unrevokable.
    """
    encoded_token, jti, _ = _encode_refresh_token(app.keypairs[keypair_index])

    blacklist_encoded_token(encoded_token)

    assert is_blacklisted(jti)


@pytest.mark.parametrize("keypair_index", [0, 1])
def test_denylist_check_covers_any_loaded_keypair(app, db_session, keypair_index):
    """A revoked token reads as revoked whichever loaded keypair signed it."""
    encoded_token, jti, exp = _encode_refresh_token(app.keypairs[keypair_index])
    blacklist_token(jti, exp)

    _, token_is_blacklisted = is_token_blacklisted(encoded_token)

    assert token_is_blacklisted
