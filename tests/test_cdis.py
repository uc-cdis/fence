import json
from .utils import cdis as utils


def test_cdis_create_api_key(client, oauth_client):
    """
    Test ``POST /credentials/cdis``.
    """
    res = utils.get_api_key_with_json(client).json
    assert 'key_id' in res
    assert 'api_key' in res


def test_cdis_get_access_token(client, oauth_client):
    """
    Test ``POST /credentials/cdis/access_token``.
    """
    response = utils.get_api_key(client)
    api_key = response.json['api_key']
    path = (
        '/credentials/cdis/access_token'
    )
    data = {
        'api_key': api_key,
    }
    headers = {
        'Content-Type': 'application/json'
    }
    response = client.post(path, data=json.dumps(data), headers=headers)
    assert 'access_token' in response.json


def test_cdis_get_access_token_with_formdata(client, oauth_client):
    """
    Test ``POST /credentials/cdis``.
    """
    response = utils.get_api_key(client)
    api_key = response.json['api_key']
    path = (
        '/credentials/cdis/access_token'
    )
    data = {
        'api_key': api_key,
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = client.post(path, data=data, headers=headers)
    assert 'access_token' in response.json


def test_cdis_list_api_key(client, oauth_client):
    utils.get_api_key(client)
    utils.get_api_key(client)
    utils.get_api_key(client)
    path = (
        '/credentials/cdis/'
    )
    response = client.get(path)
    assert 'jtis' in response.json
    assert len(response.json['jtis']) == 3
    assert response.status_code == 200
