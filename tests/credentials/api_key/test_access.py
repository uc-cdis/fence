"""
Test using an API key to generate an access token.
"""

import json

from tests.utils.api_key import get_api_key


def test_cdis_get_access_token(client, oauth_client, encoded_creds_jwt_user_id_client_id):
    """
    Test ``POST /credentials/cdis/access_token``.
    """
    encoded_credentials_jwt, _, _ = encoded_creds_jwt_user_id_client_id
    response = get_api_key(client, encoded_credentials_jwt)
    api_key = response.json['api_key']
    path = '/credentials/cdis/access_token'
    data = {'api_key': api_key}
    response = client.post(path, data=data,
        headers={'Authorization': 'Bearer ' + str(encoded_credentials_jwt)})
    assert 'access_token' in response.json


def test_cdis_get_access_token_with_formdata(
        client, oauth_client, encoded_creds_jwt_user_id_client_id):
    """
    Test ``POST /credentials/cdis``.
    """
    encoded_credentials_jwt, _, _ = encoded_creds_jwt_user_id_client_id
    response = get_api_key(client, encoded_credentials_jwt)
    api_key = response.json['api_key']
    path = '/credentials/cdis/access_token'
    data = {'api_key': api_key}
    response = client.post(path, data=data,
        headers={'Authorization': 'Bearer ' + str(encoded_credentials_jwt)})
    assert 'access_token' in response.json
