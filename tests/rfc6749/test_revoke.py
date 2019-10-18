from fence.jwt.blacklist import is_token_blacklisted

from tests.utils.oauth2 import create_basic_header_for_client


def test_blacklisted_token(client, oauth_client, encoded_jwt_refresh_token):
    """
    Revoke a JWT and test that it registers as blacklisted.
    """
    headers = create_basic_header_for_client(oauth_client)
    data = {'token': encoded_jwt_refresh_token}
    response = client.post('/oauth2/revoke', headers=headers, data=data)
    print(encoded_jwt_refresh_token)
    import jwt
    print(jwt.decode(encoded_jwt_refresh_token, verify=False))
    assert response.status_code == 204, response.data
    assert is_token_blacklisted(encoded_jwt_refresh_token)


def test_cannot_revoke_access_token(client, oauth_client, encoded_jwt):
    """
    Test that attempting to revoke an access token fails and returns 400.
    """
    headers = create_basic_header_for_client(oauth_client)
    data = {'token': encoded_jwt}
    response = client.post('/oauth2/revoke', headers=headers, data=data)
    assert response.status_code == 400, response.data
