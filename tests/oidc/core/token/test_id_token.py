import pytest
import time

from authlib.specs.oidc import IDTokenError
from fence.resources.storage.cdis_jwt import create_id_token

from fence.jwt.token import generate_signed_id_token, UnsignedIDToken
from fence.jwt.validate import validate_jwt
from fence.models import User
from fence.utils import random_str

from tests import test_settings
from tests.utils import oauth2


def test_create_id_token(app):
    """
    Naive ID Token generation test. Just makes sure there are no exceptions and
    something is created.
    """
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000

    token = create_id_token(
        user=user, keypair=keypair, expires_in=expires_in,
        client_id=client_id, audiences=[client_id],
        auth_time=None, max_age=None, nonce=None
    )

    assert token is not None


def test_recode_id_token(app, private_key):
    """
    Test that after signing, unsigning, re-signing, and unsigning again,
    the contents of the ID Token that should be the same, are.
    """
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    issuer = app.config.get('BASE_URL')
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000
    nonce = "a1b2c3d4e5f6g7h8i9j0k!l@#n$%^q&*stuvwxyz"
    max_age = None

    original_signed_token = create_id_token(
        user=user, keypair=keypair, expires_in=expires_in,
        client_id=client_id, audiences=[client_id],
        auth_time=None, max_age=max_age, nonce=nonce
    )
    original_unsigned_token = UnsignedIDToken.from_signed_and_encoded_token(
        original_signed_token, client_id=client_id, issuer=issuer,
        max_age=max_age, nonce=nonce)

    new_signed_token = original_unsigned_token.get_signed_and_encoded_token(
        kid, private_key
    )
    new_unsigned_token = UnsignedIDToken.from_signed_and_encoded_token(
        new_signed_token, client_id=client_id, issuer=issuer,
        max_age=max_age, nonce=nonce
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
    issuer = app.config.get('BASE_URL')
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000
    nonce = "a1b2c3d4e5f6g7h8i9j0k!l@#n$%^q&*stuvwxyz"
    max_age = None

    signed_token = create_id_token(
        user=user, keypair=keypair, expires_in=expires_in,
        client_id=client_id, audiences=[client_id],
        auth_time=None, max_age=max_age, nonce=nonce
    )

    unsigned_token = UnsignedIDToken.from_signed_and_encoded_token(
        signed_token, client_id=client_id, issuer=issuer,
        max_age=max_age, nonce=nonce)

    unsigned_token.validate(
        issuer=issuer, client_id=client_id, max_age=max_age, nonce=nonce
    )

    assert True


def test_valid_id_token_without_nonce(app):
    """
    Create a token and then validate it and make sure there are no exceptions
    when a nonce is not provided.
    """
    issuer = app.config.get('BASE_URL')
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000
    nonce = None
    max_age = None

    signed_token = create_id_token(
        user=user, keypair=keypair, expires_in=expires_in,
        client_id=client_id, audiences=[client_id],
        auth_time=None, max_age=max_age, nonce=nonce
    )

    unsigned_token = UnsignedIDToken.from_signed_and_encoded_token(
        signed_token, client_id=client_id, issuer=issuer,
        max_age=max_age, nonce=nonce)

    unsigned_token.validate(
        issuer=issuer, client_id=client_id, max_age=max_age, nonce=nonce
    )

    assert not unsigned_token.token.get("nonce")


def test_expired_id_token(app):
    """
    Create a token that is already expired make sure an exception is thrown.
    """
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 0
    nonce = None
    max_age = None

    with pytest.raises(IDTokenError):
        token = generate_signed_id_token(
            keypair.kid, keypair.private_key, user, expires_in, client_id,
            audiences=[client_id], auth_time=None, max_age=max_age, nonce=nonce
        )
        assert not token


def test_id_token_max_age(app):
    """
    Create a token and then validate it and make sure there are no exceptions
    when a nonce is not provided.

    FIXME: We should test that this tries to re-auth user, not throw exception
    """
    keypair = app.keypairs[0]
    client_id = "client_12345"
    user = User(username='test', is_admin=False)
    expires_in = 2592000
    nonce = None
    max_age = 1
    now = int(time.time()) - 10

    with pytest.raises(IDTokenError):
        generate_signed_id_token(
            keypair.kid, keypair.private_key, user, expires_in, client_id,
            audiences=[client_id], auth_time=now, max_age=max_age, nonce=nonce)


def test_id_token_has_nonce(client, oauth_client):
    nonce = random_str(10)
    data = {
        'client_id': oauth_client.client_id,
        'redirect_uri': oauth_client.url,
        'response_type': 'code',
        'scope': 'openid user',
        'state': random_str(10),
        'confirm': 'yes',
        'nonce': nonce,
    }
    response_json = (
        oauth2.get_token_response(client, oauth_client, code_request_data=data)
        .json
    )
    id_token = validate_jwt(response_json['id_token'], {'openid'})
    assert 'nonce' in id_token
    assert nonce == id_token['nonce']


def test_aud(client, oauth_client, id_token):
    """
    Test that the audiences of the ID token contain the OAuth client id.
    """
    id_claims = validate_jwt(id_token, {'openid'})
    assert 'aud' in id_claims
    assert oauth_client.client_id in id_claims['aud']
