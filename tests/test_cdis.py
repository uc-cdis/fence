import json
from .utils import cdis as utils


def test_cdis_create_refresh_token(client, oauth_client):
    """
    Test ``POST /credentials/cdis``.
    """
    res = utils.get_refresh_token_with_json(client).json
    assert 'token_id' in res
    assert 'refresh_token' in res


def test_cdis_get_access_token(client, oauth_client):
    """
    Test ``PUT /credentials/cdis``.
    """
    response = utils.get_refresh_token(client)
    refresh_token = response.json['refresh_token']
    path = (
        '/credentials/cdis/'
    )
    data = {
        'refresh_token': refresh_token,
    }
    headers = {
        'Content-Type': 'application/json'
    }
    response = client.put(path, data=json.dumps(data), headers=headers)
    assert 'access_token' in response.json


def test_cdis_get_access_token_with_formdata(client, oauth_client):
    """
    Test ``PUT /credentials/cdis``.
    """
    response = utils.get_refresh_token(client)
    refresh_token = response.json['refresh_token']
    path = (
        '/credentials/cdis/'
    )
    data = {
        'refresh_token': refresh_token,
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = client.put(path, data=data, headers=headers)
    assert 'access_token' in response.json


def test_cdis_list_refresh_token(client, oauth_client):
    utils.get_refresh_token(client)
    utils.get_refresh_token(client)
    utils.get_refresh_token(client)
    path = (
        '/credentials/cdis/'
    )
    response = client.get(path)
    assert 'jtis' in response.json
    assert len(response.json['jtis']) == 3
    assert response.status_code == 200
