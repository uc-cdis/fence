import urllib

from . import utils


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
    response = utils.oauth_post_authorize(client, oauth_client)
    assert response.status_code == 302
    location = response.headers['Location']
    assert location.startswith(oauth_client.url)


def test_oauth2_token_post(client, oauth_client):
    """
    Test ``POST /oauth2/token`` with a code from ``POST /oauth2/authorize``.
    """
    code = utils.code_from_authorize_response(utils.oauth_post_authorize(
        client, oauth_client
    ))
    response = utils.oauth_post_token(client, oauth_client, code)
    assert 'access_token' in response.json


def test_validate_oauth2_token(client, oauth_client):
    """
    Get an access token from going through the OAuth procedure and try to use
    it to access a protected endpoint, ``/user``.
    """
    access_token = utils.get_access_token(client, oauth_client)
    response = client.get('/user', headers={'Authorization': access_token})
    assert response
