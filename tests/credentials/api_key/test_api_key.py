from unittest import mock

import jwt
import pytest

from tests import utils
from tests.utils.api_key import get_api_key, get_api_key_with_json


def test_create_api_key(client, oauth_client, encoded_creds_jwt):
    """
    Test ``POST /credentials/api``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key_with_json(client, encoded_credentials_jwt).json
    assert "key_id" in response
    assert "api_key" in response


def test_create_api_key_with_disallowed_scope(client, oauth_client, encoded_creds_jwt):
    """
    Test ``POST /credentials/api``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt, scope=["credentials"])
    assert response.status_code == 400, response.text


def test_list_api_key(client, oauth_client, encoded_creds_jwt):
    # create API keys
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    n_keys = 3
    for _ in range(n_keys):
        get_api_key(client, encoded_credentials_jwt)

    # list existing API keys
    response = client.get(
        "/credentials/api/",
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "jtis" in response.json
    assert len(response.json["jtis"]) == n_keys


def test_delete_api_key_access(
    app,
    client,
    oauth_client,
    encoded_creds_jwt,
    kid,
    rsa_private_key,
    mock_arborist_requests,
):
    """
    Test that an admin can delete another user's API Key and that the deleted API Key cannot be used to get an access token.
    """
    response = get_api_key(client, encoded_creds_jwt["jwt"])
    assert response.status_code == 200, response.text
    key_id = response.json["key_id"]
    api_key = response.json["api_key"]

    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    revoker_jwt = jwt.encode(
        utils.authorized_download_credentials_context_claims(
            "other-user", 80, oauth_client["client_id"]
        ),
        key=rsa_private_key,
        headers={"kid": kid},
        algorithm="RS256",
    )

    with mock.patch.object(
        app.arborist, "auth_request", wraps=app.arborist.auth_request
    ) as auth_request:
        response = client.delete(
            f"/credentials/api/{key_id}",
            headers={"Authorization": f"Bearer {revoker_jwt}"},
        )
    assert response.status_code == 204

    auth_request.assert_called_once()
    assert auth_request.call_args.kwargs["user_id"] == "other-user"
    assert not auth_request.call_args.kwargs["jwt"]

    response = client.post("/credentials/api/access_token", data={"api_key": api_key})
    assert response.status_code == 401


def test_delete_api_key_not_found(client, encoded_creds_jwt, mock_arborist_requests):
    """
    Test ``DELETE /credentials/api/<jti>`` with a JTI that matches no API key
    """
    mock_arborist_requests()
    response = client.delete(
        "/credentials/api/514a2ccb-8e2e-416b-ad7c-4c52bc03e8e5",
        headers={"Authorization": "Bearer " + str(encoded_creds_jwt["jwt"])},
    )
    assert response.status_code == 404, response.text
