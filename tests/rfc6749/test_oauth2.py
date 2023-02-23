"""
Test the endpoints in the ``/oauth2`` blueprint.
"""

import jwt
import pytest

from fence.jwt.token import SCOPE_DESCRIPTION
from fence.config import config


def test_all_scopes_have_description():
    for scope in config["CLIENT_ALLOWED_SCOPES"]:
        assert scope in SCOPE_DESCRIPTION


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_oauth2_authorize(oauth_test_client, method):
    """Test ``/oauth2/authorize``."""
    data = {"confirm": "yes"}
    oauth_test_client.authorize(method=method, data=data)


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_oauth2_authorize_incorrect_scope(oauth_test_client, method):
    """Test ``/oauth2/authorize``."""
    data = {"confirm": "yes", "scope": "openid wrong_code"}
    auth_response = oauth_test_client.authorize(
        method=method, data=data, do_asserts=False
    )
    assert auth_response.response.status_code == 401


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_oauth2_authorize_get_public_client(oauth_test_client_public, method):
    """Test ``/oauth2/authorize`` with a public client."""
    data = {"confirm": "yes"}
    oauth_test_client_public.authorize(method=method, data=data)


def test_oauth2_token_post(oauth_test_client):
    """Test ``POST /oauth2/token``."""
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    oauth_test_client.token()

    response = oauth_test_client.token_response.response
    assert response.status_code == 200, response.json
    response = response.json
    assert "id_token" in response
    assert "access_token" in response
    assert "refresh_token" in response
    assert "expires_in" in response
    assert response.get("token_type") == "Bearer"

    payload = jwt.decode(
        response["access_token"],
        options={"verify_signature": False},
        algorithms=["RS256"],
    )
    assert payload.get("iss") == "http://localhost/user"
    assert payload.get("azp") == oauth_test_client.client_id
    assert "context" in payload
    assert payload.get("context", {}).get("user", {}).get("name") == "test"
    assert payload.get("scope") == ["openid", "user"]


def test_oauth2_token_post_public_client(oauth_test_client_public):
    """Test ``POST /oauth2/token`` for public client."""
    data = {"confirm": "yes"}
    oauth_test_client_public.authorize(data=data)
    oauth_test_client_public.token()


@pytest.mark.parametrize("refresh_data", [{}, {"scope": "openid"}])
def test_oauth2_token_refresh(oauth_test_client, refresh_data):
    """Test the refresh endpoint."""
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    oauth_test_client.token()
    oauth_test_client.refresh(data=refresh_data)


@pytest.mark.parametrize("refresh_data", [{}, {"scope": "openid"}])
def test_oauth2_token_refresh_public_client(oauth_test_client_public, refresh_data):
    """Test the refresh endpoint for public client."""
    data = {"confirm": "yes"}
    oauth_test_client_public.authorize(data=data)
    oauth_test_client_public.token()
    oauth_test_client_public.refresh(data=refresh_data)


def test_oauth2_token_post_revoke(oauth_test_client):
    """
    Test the following procedure:
    - ``POST /oauth2/authorize`` successfully to obtain code
    - ``POST /oauth2/token`` successfully to obtain token
    - ``POST /oauth2/revoke`` to revoke the refresh token
    - Refresh token should no longer be usable at this point.
    """
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    oauth_test_client.token()
    oauth_test_client.revoke()
    # Try to use refresh token.
    refresh_token = oauth_test_client.token_response.refresh_token
    oauth_test_client.refresh(refresh_token, do_asserts=False)
    response = oauth_test_client.refresh_response.response
    assert response.status_code == 400


def test_oauth2_with_client_credentials(
    oauth_client_with_client_credentials, oauth_test_client_with_client_credentials
):
    """
    Test that a client with the client_credentials grant can exchange its
    client ID and secret for an access token
    """
    # hit /oauth2/token
    oauth_test_client_with_client_credentials.token(
        scope=" ".join(oauth_client_with_client_credentials.scopes)
    )

    response = oauth_test_client_with_client_credentials.token_response.response
    assert response.status_code == 200, response.json
    response = response.json
    assert "access_token" in response
    assert "expires_in" in response
    assert response.get("token_type") == "Bearer"

    payload = jwt.decode(
        response["access_token"],
        options={"verify_signature": False},
        algorithms=["RS256"],
    )
    assert payload.get("iss") == "http://localhost/user"
    assert payload.get("azp") == oauth_test_client_with_client_credentials.client_id
    assert payload.get("context") == {}  # no user linked to this token
    assert payload.get("scope") == oauth_client_with_client_credentials.scopes


def test_oauth2_with_client_credentials_bad_scope(
    oauth_test_client_with_client_credentials,
):
    """
    Test that a client with the client_credentials grant cannot exchange its
    client ID and secret for an access token when requesting a scope it does
    not have
    """
    # hit /oauth2/token
    oauth_test_client_with_client_credentials.token(
        scope="openid unknown-scope", do_asserts=False
    )

    response = oauth_test_client_with_client_credentials.token_response.response
    assert response.status_code == 400, response.json
    assert response.json.get("error") == "invalid_scope"


def test_oauth2_without_client_credentials(oauth_test_client):
    """
    Test that a client without the client_credentials grant cannot exchange its
    client ID and secret for an access token
    """
    oauth_test_client.authorize(data={"confirm": "yes"})

    oauth_test_client.grant_types = ["client_credentials"]
    oauth_test_client.token(do_asserts=False)  # hit /oauth2/token
    response = oauth_test_client.token_response.response
    assert response.status_code == 400, response.json
    assert response.json.get("error") == "unauthorized_client"
