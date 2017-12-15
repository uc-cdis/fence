import urllib

from . import cdis_utils


def test_cdis_authorize(client, oauth_client):
    """
    Test ``POST /credentials/cdis``.
    """
    assert 'token' in cdis_utils.get_refresh_token(client).json


def test_cdis_get_access_token(client, oauth_client):
    """
    Test ``POST /oauth2/authorize``.
    """
    response = cdis_utils.get_refresh_token(client)
    refresh_token = response.json['token']
    path = (
        '/credentials/cdis'
    )
    data = {
        'refresh_token': refresh_token,
    }
    response = client.put(path, data=data)
    assert 'access_token' in response.json

#
#
# def test_oauth2_token_post(client, oauth_client):
#     """
#     Test ``POST /oauth2/token`` with a code from ``POST /oauth2/authorize``.
#     """
#     code = utils.code_from_authorize_response(utils.oauth_post_authorize(
#         client, oauth_client
#     ))
#     response = utils.oauth_post_token(client, oauth_client, code)
#     assert 'access_token' in response.json
#
#
# def test_validate_oauth2_token(client, oauth_client):
#     """
#     Get an access token from going through the OAuth procedure and try to use
#     it to access a protected endpoint, ``/user``.
#     """
#     access_token = utils.get_access_token(client, oauth_client)
#     response = client.get('/user', headers={'Authorization': access_token})
#     assert response
