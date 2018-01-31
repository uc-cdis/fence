from tests.utils.api_key import get_api_key, get_api_key_with_json


def test_cdis_create_api_key(client, oauth_client):
    """
    Test ``POST /credentials/cdis``.
    """
    response = get_api_key_with_json(client).json
    assert 'key_id' in response
    assert 'api_key' in response


def test_cdis_create_api_key_with_disallowed_scope(client, oauth_client):
    """
    Test ``POST /credentials/cdis``.
    """
    response = get_api_key(client, scope=['credentials'])
    assert response.status_code == 400


def test_cdis_list_api_key(client, oauth_client):
    n_keys = 3
    for _ in range(n_keys):
        get_api_key(client)
    response = client.get('/credentials/cdis/')
    assert 'jtis' in response.json
    assert len(response.json['jtis']) == n_keys
    assert response.status_code == 200
