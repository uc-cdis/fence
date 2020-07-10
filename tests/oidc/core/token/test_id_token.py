import pytest
import time

from authlib.jose.errors import InvalidClaimError

from fence.jwt.token import (
    generate_signed_id_token,
    UnsignedCodeIDToken,
    UnsignedIDToken,
)
from fence.jwt.validate import validate_jwt
from fence.models import User
from fence.utils import random_str
from fence.config import config


def test_recode_id_token(app, kid, rsa_private_key):
    """
    Test that after signing, unsigning, re-signing, and unsigning again,
    the contents of the ID Token that should be the same, are.
    """
    issuer = config.get("BASE_URL")
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username="test", is_admin=False)
    expires_in = 2592000
    nonce = "a1b2c3d4e5f6g7h8i9j0k!l@#n$%^q&*stuvwxyz"
    max_age = None

    original_signed_token = generate_signed_id_token(
        keypair.kid,
        keypair.private_key,
        user,
        expires_in,
        client_id,
        audiences=[client_id],
        auth_time=None,
        max_age=max_age,
        nonce=nonce,
    )
    original_unsigned_token = UnsignedCodeIDToken.from_signed_and_encoded_token(
        original_signed_token.token,
        client_id=client_id,
        issuer=issuer,
        max_age=max_age,
        nonce=nonce,
    )

    new_signed_token = original_unsigned_token.get_signed_and_encoded_token(
        kid, rsa_private_key
    )
    new_unsigned_token = UnsignedCodeIDToken.from_signed_and_encoded_token(
        new_signed_token,
        client_id=client_id,
        issuer=issuer,
        max_age=max_age,
        nonce=nonce,
    )

    assert original_unsigned_token.iss == new_unsigned_token.iss
    assert original_unsigned_token.sub == new_unsigned_token.sub
    assert original_unsigned_token.aud == new_unsigned_token.aud
    assert original_unsigned_token.azp == new_unsigned_token.azp
    assert original_unsigned_token.nonce == new_unsigned_token.nonce


def test_valid_id_token(app):
    """
    Create a token and then validate it and make sure there are no exceptions
    """
    issuer = config.get("BASE_URL")
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username="test", is_admin=False)
    expires_in = 2592000
    nonce = "a1b2c3d4e5f6g7h8i9j0k!l@#n$%^q&*stuvwxyz"
    max_age = None
    token_result = generate_signed_id_token(
        keypair.kid,
        keypair.private_key,
        user,
        expires_in,
        client_id,
        audiences=[client_id],
        auth_time=None,
        max_age=None,
        nonce=None,
    )
    unsigned_token = UnsignedIDToken.from_signed_and_encoded_token(
        token_result.token,
        client_id=client_id,
        issuer=issuer,
        max_age=max_age,
        nonce=nonce,
    )
    unsigned_token.validate()


def test_valid_id_token_without_nonce(app):
    """
    Create a token and then validate it and make sure there are no exceptions
    when a nonce is not provided.
    """
    issuer = config.get("BASE_URL")
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username="test", is_admin=False)
    expires_in = 2592000
    nonce = None
    max_age = None
    token_result = generate_signed_id_token(
        keypair.kid,
        keypair.private_key,
        user,
        expires_in,
        client_id,
        audiences=[client_id],
        auth_time=None,
        max_age=None,
        nonce=None,
    )
    unsigned_token = UnsignedIDToken.from_signed_and_encoded_token(
        token_result.token,
        client_id=client_id,
        issuer=issuer,
        max_age=max_age,
        nonce=nonce,
    )
    unsigned_token.validate()
    assert not unsigned_token.get("nonce")


def test_id_token_has_nonce(oauth_test_client):
    nonce = random_str(10)
    data = {"confirm": "yes", "nonce": nonce}
    oauth_test_client.authorize(data=data)
    response_json = oauth_test_client.token(data=data).response.json
    id_token = validate_jwt(response_json["id_token"], {"openid"})
    assert "nonce" in id_token
    assert nonce == id_token["nonce"]


def test_aud(client, oauth_client, id_token):
    """
    Test that the audiences of the ID token contain the OAuth client id.
    """
    id_claims = validate_jwt(id_token, {"openid"})
    assert "aud" in id_claims
    assert oauth_client.client_id in id_claims["aud"]
