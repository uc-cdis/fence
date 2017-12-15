from fence.jwt.blacklist import (
    blacklist_token,
    is_blacklisted,
    is_token_blacklisted,
)

from tests import oauth2_utils


def test_jti_not_blacklisted(app):
    """
    Test checking a ``jti`` which has not been blacklisted.
    """
    assert not is_blacklisted(oauth2_utils.new_jti())


def test_blacklist(app):
    """
    Test blacklisting a ``jti`` directly.
    """
    _, exp = oauth2_utils.iat_and_exp()
    jti = oauth2_utils.new_jti()
    blacklist_token(jti, exp)
    assert is_blacklisted(jti)


def test_normal_token_not_blacklisted(app, encoded_jwt_refresh_token):
    """
    Test that a (refresh) token which was not blacklisted returns not
    blacklisted.
    """
    assert not is_token_blacklisted(encoded_jwt_refresh_token)


def test_blacklisted_token(client, encoded_jwt_refresh_token):
    """
    Revoke a JWT and test that it registers as blacklisted.
    """
    data = {'token': encoded_jwt_refresh_token}
    response = client.post('/oauth2/revoke', data=data)
    assert response.status_code == 204, response.data
    assert is_token_blacklisted(encoded_jwt_refresh_token)


def test_cannot_revoke_access_token(client, encoded_jwt):
    """
    Test that attempting to revoke an access token fails and returns 400.
    """
    data = {'token': encoded_jwt}
    response = client.post('/oauth2/revoke', data=data)
    assert response.status_code == 400, response.data
