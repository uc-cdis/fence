from fence.jwt.blacklist import is_token_blacklisted


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
