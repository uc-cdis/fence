"""
Test the endpoints in the ``/oauth2`` blueprint.
"""

import urllib

import tests.utils.oauth2
from fence.jwt.token import SCOPE_DESCRIPTION, CLIENT_ALLOWED_SCOPES


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
    response = tests.utils.oauth2.post_authorize(client, oauth_client, confirm=True)
    assert response.status_code == 302, response
    location = response.headers['Location']
    assert location.startswith(oauth_client.url), location


def test_oauth2_token_post(client, oauth_client):
    """
    Test ``POST /oauth2/token`` with a code from ``POST /oauth2/authorize``.
    """
    code = tests.utils.oauth2.get_access_code(client, oauth_client)
    response = tests.utils.oauth2.post_token(client, oauth_client, code)
    assert 'access_token' in response.json
    assert 'refresh_token' in response.json


def test_oauth2_token_refresh(client, oauth_client, refresh_token):
    """
    Obtain refresh and access tokens, and test using the refresh token to
    obtain a new access token.
    """
    code = tests.utils.oauth2.get_access_code(client, oauth_client)
    headers = tests.utils.oauth2.create_basic_header_for_client(oauth_client)
    data = {
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'code': code,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }
    response = client.post('/oauth2/token', headers=headers, data=data)
    assert response.status_code == 200, response.json


def test_oauth2_token_post_revoke(client, oauth_client, refresh_token):
    """
    Test the following procedure:
    - ``POST /oauth2/authorize`` successfully to obtain code
    - ``POST /oauth2/token`` successfully to obtain token
    - ``POST /oauth2/revoke`` to revoke the refresh token
    - Refresh token should no longer be usable at this point.
    """
    # Revoke refresh token.
    client.post('/oauth2/revoke', data={'token': refresh_token})
    # Try to use refresh token.
    code = tests.utils.oauth2.get_access_code(client, oauth_client)
    data = {
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'code': code,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }
    response = client.post('/oauth2/token', data=data)
    assert response.status_code == 401


def test_all_scopes_have_description():
    for scope in CLIENT_ALLOWED_SCOPES:
        assert scope in SCOPE_DESCRIPTION
