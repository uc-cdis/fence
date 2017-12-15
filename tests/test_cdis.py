import urllib

from .utils import cdis as utils


def test_cdis_create_refresh_token(client, oauth_client):
    """
    Test ``POST /credentials/cdis``.
    """
    assert 'token' in utils.get_refresh_token(client).json


def test_cdis_get_access_token(client, oauth_client):
    """
    Test ``PUT /credentials/cdis``.
    """
    response = utils.get_refresh_token(client)
    refresh_token = response.json['token']
    path = (
        '/credentials/cdis/'
    )
    data = {
        'refresh_token': refresh_token,
    }
    response = client.put(path, data=data)
    assert 'access_token' in response.json
