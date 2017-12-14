import urllib

from . import oauth2_utils


def test_oauth2_authorize_get(client, oauth_client):
    """
    Test ``GET /oauth2/authorize``.
    """
    path = (
        '/oauth2/authorize'
        '?client_id={client_id}'
        '&response_type=code'
        '&scope=user'
        '&redirect_uri={redirect_uri}'
    )
    path = path.format(
        client_id=oauth_client.client_id,
        redirect_uri=urllib.quote_plus(oauth_client.url)
    )
    response = client.get(path)
    assert response.status_code == 200


def test_oauth2_authorize_post(client, oauth_client):
    """
    Test ``POST /oauth2/authorize``.
    """
    response = oauth2_utils.oauth_post_authorize(client, oauth_client)
    assert response.status_code == 302
    location = response.headers['Location']
    assert location.startswith(oauth_client.url)


def test_oauth2_token_post(client, oauth_client):
    """
    Test ``POST /oauth2/token`` with a code from ``POST /oauth2/authorize``.
    """
    code = oauth2_utils.get_access_code(client, oauth_client)
    response = oauth2_utils.oauth_post_token(client, oauth_client, code)
    assert 'access_token' in response.json
    assert 'refresh_token' in response.json


def test_oauth2_token_refresh(client, oauth_client):
    """
    Obtain refresh and access tokens, and test using the refresh token to
    obtain a new access token.
    """
    token_response = oauth2_utils.get_token_response(client, oauth_client)
    refresh_token = token_response.json['refresh_token']
    code = oauth2_utils.get_access_code(client, oauth_client)
    data = {
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'code': code,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }
    response = client.post('/oauth2/token', data=data)
    assert response.status_code == 200, response.json


def test_oauth2_token_post_revoke(client, oauth_client):
    """
    Test the following procedure:
    - ``POST /oauth2/authorize`` successfully to obtain code
    - ``POST /oauth2/token`` successfully to obtain token
    - ``POST /oauth2/revoke`` to revoke the refresh token
    - Refresh token should no longer be usable at this point.
    """
    # Get code and get refresh token.
    token_response = oauth2_utils.get_token_response(client, oauth_client)
    refresh_token = token_response.json['refresh_token']
    # Revoke refresh token.
    client.post('/oauth2/revoke', data={'token': refresh_token})
    # Try to use refresh token.
    code = oauth2_utils.get_access_code(client, oauth_client)
    data = {
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'code': code,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }
    response = client.post('/oauth2/token', data=data)
    assert response.status_code == 401


def test_validate_oauth2_token(client, oauth_client):
    """
    Get an access token from going through the OAuth procedure and try to use
    it to access a protected endpoint, ``/user``.
    """
    token_response = oauth2_utils.get_token_response(client, oauth_client)
    access_token = token_response.json['access_token']
    response = client.get('/user', headers={'Authorization': access_token})
    assert response
