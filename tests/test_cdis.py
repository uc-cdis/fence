from tests.utils import cdis


def test_cdis_create_refresh_token(client, oauth_client):
    """
    Test ``POST /credentials/cdis``.
    """
    assert 'token' in cdis.get_refresh_token(client).json


def test_cdis_get_access_token(client, oauth_client):
    """
    Test ``PUT /credentials/cdis``.
    """
    response = cdis.get_refresh_token(client)
    assert 'token' in response.json
    refresh_token = response.json['token']
    path = (
        '/credentials/cdis/'
    )
    data = {
        'refresh_token': refresh_token,
        'scope': 'fence',
    }
    response = client.put(path, data=data)
    assert 'access_token' in response.json
