from tests.utils.api_key import get_api_key, get_api_key_with_json


def test_cdis_create_api_key(client, oauth_client, encoded_creds_jwt):
    """
    Test ``POST /credentials/cdis``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key_with_json(client, encoded_credentials_jwt).json
    assert "key_id" in response
    assert "api_key" in response


def test_cdis_create_api_key_with_disallowed_scope(
    client, oauth_client, encoded_creds_jwt
):
    """
    Test ``POST /credentials/cdis``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt, scope=["credentials"])
    assert response.status_code == 400


def test_cdis_list_api_key(client, oauth_client, encoded_creds_jwt):
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    n_keys = 3
    for _ in range(n_keys):
        get_api_key(client, encoded_credentials_jwt)
    response = client.get(
        "/credentials/cdis/",
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert "jtis" in response.json
    assert len(response.json["jtis"]) == n_keys
    assert response.status_code == 200
