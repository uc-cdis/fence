"""
Tests for fence.oidc.jwt_generator.

Covers:
- generate_client_response(): scope as string (split), empty scope, normal flow
- generate_token(): client_credentials dispatch → generate_client_response
- generate_implicit_response(): scope as string path
"""

import time
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# generate_client_response() tests — called directly within app context
# ---------------------------------------------------------------------------


def _mock_client(client_id="test-client"):
    client = MagicMock()
    client.client_id = client_id
    # allowed_scopes must be a list for validate_scopes
    client.allowed_scopes = ["openid", "user", "data"]
    client.scope = "openid user data"
    return client


def test_generate_client_response_scope_as_string_is_split(app):
    """scope passed as space-separated string should be split into a list."""
    from fence.oidc.jwt_generator import generate_client_response

    client = _mock_client()
    with app.test_request_context("/"):
        result = generate_client_response(client, scope="openid user")

    assert result["token_type"] == "Bearer"
    assert "access_token" in result
    # scope in response should be the original joined string
    assert "openid" in result["scope"]
    assert "user" in result["scope"]


def test_generate_client_response_empty_scope(app):
    """scope=None or scope=[] should produce empty scope in response."""
    from fence.oidc.jwt_generator import generate_client_response

    client = _mock_client()
    with app.test_request_context("/"):
        result = generate_client_response(client, scope=None)

    assert result["token_type"] == "Bearer"
    assert "access_token" in result
    assert result["scope"] == ""


def test_generate_client_response_normal_flow(app):
    """generate_client_response with list scope produces expected keys."""
    from fence.oidc.jwt_generator import generate_client_response

    client = _mock_client()
    with app.test_request_context("/"):
        result = generate_client_response(client, scope=["openid", "user"])

    assert "access_token" in result
    assert "expires_in" in result
    assert result["token_type"] == "Bearer"
    assert isinstance(result["expires_in"], int)


def test_generate_client_response_returns_string_scope(app):
    """The response scope field must be a string, not a list."""
    from fence.oidc.jwt_generator import generate_client_response

    client = _mock_client()
    with app.test_request_context("/"):
        result = generate_client_response(client, scope=["openid", "user"])

    assert isinstance(result["scope"], str)


# ---------------------------------------------------------------------------
# generate_token() dispatch test — client_credentials → generate_client_response
# ---------------------------------------------------------------------------


def test_generate_token_dispatches_to_client_response_for_client_credentials(app):
    """generate_token routes client_credentials grant to generate_client_response."""
    from fence.oidc.jwt_generator import generate_token

    client = _mock_client()

    # validate_scopes is called first; patch it out to not raise
    with patch("fence.oidc.jwt_generator.validate_scopes"), app.test_request_context(
        "/"
    ):
        result = generate_token(client, "client_credentials", scope=["openid"])

    assert result is not None
    assert "access_token" in result
    assert result["token_type"] == "Bearer"


# ---------------------------------------------------------------------------
# generate_client_response via HTTP (client_credentials grant) —
# exercises the full request path including scope normalization
# ---------------------------------------------------------------------------


def test_client_credentials_token_endpoint_returns_access_token(
    oauth_test_client_with_client_credentials,
):
    """Full client_credentials token request returns a valid access_token."""
    token_response = oauth_test_client_with_client_credentials.token()
    assert token_response.response.status_code == 200, token_response.response.json
    data = token_response.response.json
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert "expires_in" in data


def test_client_credentials_token_has_string_scope(
    oauth_test_client_with_client_credentials,
):
    """The scope in the client_credentials response is a space-separated string."""
    token_response = oauth_test_client_with_client_credentials.token()
    data = token_response.response.json
    assert isinstance(data.get("scope", ""), str)


def test_client_credentials_token_with_requested_scope(
    oauth_test_client_with_client_credentials,
):
    """A specific scope can be requested and is reflected in the response."""
    token_response = oauth_test_client_with_client_credentials.token(scope="openid")
    assert token_response.response.status_code == 200
    data = token_response.response.json
    assert "access_token" in data


# ---------------------------------------------------------------------------
# generate_implicit_response() — scope as string path
# ---------------------------------------------------------------------------


def test_generate_implicit_response_scope_string_is_split(app, oauth_user, db_session):
    """When scope is a string, generate_implicit_response splits it into a list."""
    from fence.oidc.jwt_generator import generate_implicit_response
    from fence.models import User

    # Fetch the actual user from the db so the session check works
    user = db_session.query(User).filter_by(id=oauth_user.user_id).first()
    assert user is not None

    client = _mock_client()

    with patch(
        "fence.oidc.jwt_generator.get_linked_google_account_email", return_value=None
    ), patch(
        "fence.oidc.jwt_generator.get_linked_google_account_exp", return_value=None
    ), app.test_request_context(
        "/"
    ):
        result = generate_implicit_response(
            client,
            grant_type="implicit",
            user=user,
            scope="openid user",
            nonce="test-nonce-value",
        )

    assert "id_token" in result
    assert "access_token" in result
    assert result["token_type"] == "Bearer"
