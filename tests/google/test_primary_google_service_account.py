import pytest
from unittest.mock import MagicMock, patch


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


def test_primary_google_service_account_valid(
    client,
    app,
    db_session,
    encoded_jwt_google_data_access,
    primary_google_service_account_google,
):
    """
    Test that given valid credentials, the endpoint responds with the user's primary
    google SA in the response and it matches the mocked value setup in the fixture
    """
    encoded_creds_jwt = encoded_jwt_google_data_access["jwt"]
    mock = primary_google_service_account_google["get_or_create_service_account_mock"]
    email = primary_google_service_account_google["email"]

    response = client.post(
        "/google/primary_google_service_account",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.json.get("primary_google_service_account") == email


def test_primary_google_service_account_invalid(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    primary_google_service_account_google,
):
    """
    Test that given invalid credentials (e.g. doesn't have the right scope),
    this endpoint responds with an HTTP error code and no data

    NOTE: encoded_jwt_service_accounts_access does not have the expected claim in the
          mocked token.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    mock = primary_google_service_account_google["get_or_create_service_account_mock"]
    email = primary_google_service_account_google["email"]

    response = client.post(
        "/google/primary_google_service_account",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
    )
    assert response.status_code == 401
    assert not (response.json or {}).get("primary_google_service_account")


def test_primary_google_service_account_no_creds(
    client,
    app,
    db_session,
    primary_google_service_account_google,
):
    """
    Test that given no creds, this endpoint responds with an HTTP error code and no data
    """
    mock = primary_google_service_account_google["get_or_create_service_account_mock"]
    email = primary_google_service_account_google["email"]

    response = client.post(
        "/google/primary_google_service_account",
        content_type="application/json",
    )
    assert response.status_code == 401
    assert not (response.json or {}).get("primary_google_service_account")
