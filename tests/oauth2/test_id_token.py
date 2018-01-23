# from authlib.specs.oidc import parse_id_token, validate_id_token

# token, header = parse_id_token(resp['id_token'], keys)
# validate_id_token(token, header=header, response_type='code', ...)
import pytest
import time

from fence.jwt.token import generate_signed_id_token
from fence.jwt.token import UnsignedIDToken
from fence.resources.storage.cdis_jwt import create_id_token
from fence.models import User
from tests import test_settings


def test_create_id_token(app):
    """
    Naive ID Token generation test. Just makes sure there are no exceptions and
    something is created.
    """
    keypair = app.keypairs[0]
    scopes = []
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000

    token = create_id_token(
        user=user, keypair=keypair, expires_in=expires_in,
        scopes=scopes, client_id=client_id, audiences=[client_id],
        auth_time=None, max_age=None, nonce=None
    )

    assert token is not None


def test_recode_id_token(app, private_key):
    """
    Test that after signing, unsigning, re-signing, and unsigning again,
    the contents of the ID Token that should be the same, are.
    """
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    issuer = app.config.get('HOST_NAME')
    keypair = app.keypairs[0]
    scopes = []
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000
    nonce = "a1b2c3d4e5f6g7h8i9j0k!l@#n$%^q&*stuvwxyz"
    max_age = None

    original_signed_token = create_id_token(
        user=user, keypair=keypair, expires_in=expires_in,
        scopes=scopes, client_id=client_id, audiences=[client_id],
        auth_time=None, max_age=max_age, nonce=nonce
    )
    original_unsigned_token = UnsignedIDToken.from_signed_token(
        original_signed_token, client_id=client_id, issuers=[issuer],
        max_age=max_age, nonce=nonce)

    new_signed_token = original_unsigned_token.get_signed_token(kid, private_key)
    new_unsigned_token = UnsignedIDToken.from_signed_token(
        new_signed_token, client_id=client_id, issuers=[issuer],
        max_age=max_age, nonce=nonce)

    assert original_unsigned_token.iss == new_unsigned_token.iss
    assert original_unsigned_token.sub == new_unsigned_token.sub
    assert original_unsigned_token.aud == new_unsigned_token.aud
    assert original_unsigned_token.azp == new_unsigned_token.azp
    assert original_unsigned_token.nonce == new_unsigned_token.nonce


def test_valid_id_token(app):
    """
    Create a token and then validate it and make sure there are no exceptions
    """
    issuer = app.config.get('HOST_NAME')
    keypair = app.keypairs[0]
    scopes = []
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000
    nonce = "a1b2c3d4e5f6g7h8i9j0k!l@#n$%^q&*stuvwxyz"
    max_age = None

    signed_token = create_id_token(
        user=user, keypair=keypair, expires_in=expires_in,
        scopes=scopes, client_id=client_id, audiences=[client_id],
        auth_time=None, max_age=max_age, nonce=nonce
    )

    unsigned_token = UnsignedIDToken.from_signed_token(
        signed_token, client_id=client_id, issuers=[issuer],
        max_age=max_age, nonce=nonce)

    unsigned_token.validate(issuers=[issuer], client_id=client_id, max_age=max_age, nonce=nonce)

    assert True


def test_valid_id_token_without_nonce(app):
    """
    Create a token and then validate it and make sure there are no exceptions
    when a nonce is not provided.
    """
    issuer = app.config.get('HOST_NAME')
    keypair = app.keypairs[0]
    scopes = []
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000
    nonce = None
    max_age = None

    signed_token = create_id_token(
        user=user, keypair=keypair, expires_in=expires_in,
        scopes=scopes, client_id=client_id, audiences=[client_id],
        auth_time=None, max_age=max_age, nonce=nonce
    )

    unsigned_token = UnsignedIDToken.from_signed_token(
        signed_token, client_id=client_id, issuers=[issuer],
        max_age=max_age, nonce=nonce)

    unsigned_token.validate(issuers=[issuer], client_id=client_id, max_age=max_age, nonce=nonce)

    assert not unsigned_token.token.get("nonce")


def test_expired_id_token(app):
    """
    Create a token and then validate it and make sure there are no exceptions
    when a nonce is not provided.
    """
    issuer = app.config.get('HOST_NAME')
    keypair = app.keypairs[0]
    scopes = []
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 0
    nonce = None
    max_age = None

    with pytest.raises(Exception):
        token = generate_signed_id_token(
            keypair.kid, keypair.private_key, user, expires_in, scopes, client_id,
            audiences=[client_id], auth_time=None, max_age=max_age, nonce=nonce)
        assert not token


def test_id_token_max_age(app):
    """
    Create a token and then validate it and make sure there are no exceptions
    when a nonce is not provided.

    FIXME: We should test that this tries to re-auth user, not throw exception
    """
    issuer = app.config.get('HOST_NAME')
    keypair = app.keypairs[0]
    scopes = []
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000
    nonce = None
    max_age = 1
    now = int(time.time()) - 10

    with pytest.raises(Exception):
        generate_signed_id_token(
            keypair.kid, keypair.private_key, user, expires_in, scopes, client_id,
            audiences=[client_id], auth_time=now, max_age=max_age, nonce=nonce)
