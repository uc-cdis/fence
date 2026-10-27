"""
Tests for fence.oidc.endpoints.

Covers:
- JWTIntrospectionToken: is_expired, is_revoked, check_client
- IntrospectionEndpoint.introspect_token: payload fields, scope handling, context claims
- IntrospectionEndpoint.query_token: valid JWT → token object, invalid JWT → None
- RevocationEndpoint.query_token and revoke_token via HTTP
- JWTToken: client matching via revoke endpoint
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from fence.oidc.endpoints import JWTIntrospectionToken, IntrospectionEndpoint
from tests.utils.oauth2 import create_basic_header


# ---------------------------------------------------------------------------
# JWTIntrospectionToken unit tests
# ---------------------------------------------------------------------------


def test_jwt_introspection_token_expired_when_exp_in_past():
    token = JWTIntrospectionToken({"exp": int(time.time()) - 60})
    assert token.is_expired() is True


def test_jwt_introspection_token_not_expired_when_exp_in_future():
    token = JWTIntrospectionToken({"exp": int(time.time()) + 3600})
    assert token.is_expired() is False


def test_jwt_introspection_token_not_expired_without_exp():
    """No exp claim → treated as epoch 0, which is in the past → expired."""
    token = JWTIntrospectionToken({})
    assert token.is_expired() is True


def test_jwt_introspection_token_is_revoked_when_jti_blacklisted():
    with patch("fence.jwt.blacklist.is_blacklisted", return_value=True):
        token = JWTIntrospectionToken({"jti": "some-jti"})
        assert token.is_revoked() is True


def test_jwt_introspection_token_not_revoked_when_jti_not_blacklisted():
    with patch("fence.jwt.blacklist.is_blacklisted", return_value=False):
        token = JWTIntrospectionToken({"jti": "some-jti"})
        assert token.is_revoked() is False


def test_jwt_introspection_token_not_revoked_when_no_jti():
    """Without a jti, the token is considered not revoked."""
    token = JWTIntrospectionToken({})
    assert token.is_revoked() is False


def test_jwt_introspection_token_check_client_matches():
    client = MagicMock()
    client.client_id = "my-client"
    token = JWTIntrospectionToken({"azp": "my-client"})
    assert token.check_client(client) is True


def test_jwt_introspection_token_check_client_mismatches():
    client = MagicMock()
    client.client_id = "other-client"
    token = JWTIntrospectionToken({"azp": "my-client"})
    assert token.check_client(client) is False


def test_jwt_introspection_token_check_client_no_azp():
    client = MagicMock()
    client.client_id = "my-client"
    token = JWTIntrospectionToken({})
    assert token.check_client(client) is False


# ---------------------------------------------------------------------------
# IntrospectionEndpoint.introspect_token() unit tests
# ---------------------------------------------------------------------------


def _make_endpoint():
    """Return an IntrospectionEndpoint instance with mocked server/request."""
    endpoint = IntrospectionEndpoint.__new__(IntrospectionEndpoint)
    return endpoint


def test_introspect_token_basic_payload():
    endpoint = _make_endpoint()
    claims = {
        "scope": "openid user",
        "azp": "test-client",
        "sub": "user-123",
        "iss": "http://localhost/user",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "jti": "jwt-id-abc",
    }
    token = JWTIntrospectionToken(claims)
    payload = endpoint.introspect_token(token)

    assert payload["scope"] == "openid user"
    assert payload["client_id"] == "test-client"
    assert payload["sub"] == "user-123"
    assert payload["iss"] == "http://localhost/user"
    assert payload["jti"] == "jwt-id-abc"
    assert payload["token_type"] == "Bearer"
    assert payload.get("active") is None  # parent adds active, not us


def test_introspect_token_scope_as_list_joined():
    endpoint = _make_endpoint()
    claims = {"scope": ["openid", "user", "data"]}
    token = JWTIntrospectionToken(claims)
    payload = endpoint.introspect_token(token)
    assert payload["scope"] == "openid user data"


def test_introspect_token_scope_as_string_unchanged():
    endpoint = _make_endpoint()
    claims = {"scope": "openid user"}
    token = JWTIntrospectionToken(claims)
    payload = endpoint.introspect_token(token)
    assert payload["scope"] == "openid user"


def test_introspect_token_includes_username_from_context():
    endpoint = _make_endpoint()
    claims = {
        "context": {"user": {"name": "alice"}},
    }
    token = JWTIntrospectionToken(claims)
    payload = endpoint.introspect_token(token)
    assert payload["username"] == "alice"


def test_introspect_token_includes_patient_id_from_context():
    endpoint = _make_endpoint()
    claims = {
        "context": {"patient": "patient-xyz"},
    }
    token = JWTIntrospectionToken(claims)
    payload = endpoint.introspect_token(token)
    assert payload["patient"] == "patient-xyz"


def test_introspect_token_omits_none_values():
    endpoint = _make_endpoint()
    claims = {}  # all optional fields absent
    token = JWTIntrospectionToken(claims)
    payload = endpoint.introspect_token(token)
    # None values must be filtered out (except token_type which is always set)
    assert "sub" not in payload
    assert "iss" not in payload
    assert "jti" not in payload
    assert payload["token_type"] == "Bearer"


def test_introspect_token_no_username_when_context_user_missing():
    endpoint = _make_endpoint()
    claims = {"context": {}}
    token = JWTIntrospectionToken(claims)
    payload = endpoint.introspect_token(token)
    assert "username" not in payload


def test_introspect_token_no_patient_when_context_patient_missing():
    endpoint = _make_endpoint()
    claims = {"context": {"user": {"name": "alice"}}}
    token = JWTIntrospectionToken(claims)
    payload = endpoint.introspect_token(token)
    assert "patient" not in payload


# ---------------------------------------------------------------------------
# IntrospectionEndpoint.query_token unit tests  (require app context + valid JWT)
# ---------------------------------------------------------------------------


def test_introspect_query_token_returns_token_for_valid_jwt(
    app, encoded_jwt, kid, rsa_public_key
):
    """query_token wraps a valid JWT in a JWTIntrospectionToken."""
    endpoint = _make_endpoint()
    result = endpoint.query_token(encoded_jwt, "access_token")
    assert result is not None
    assert isinstance(result, JWTIntrospectionToken)


def test_introspect_query_token_returns_none_for_invalid_jwt(app):
    """query_token returns None for a JWT that cannot be validated."""
    endpoint = _make_endpoint()
    result = endpoint.query_token("not.a.jwt", None)
    assert result is None


# ---------------------------------------------------------------------------
# Revocation endpoint HTTP tests — covers query_token, revoke_token, JWTToken
# ---------------------------------------------------------------------------


def test_revoke_endpoint_success_with_valid_credentials(
    client, oauth_client, encoded_jwt_refresh_token
):
    """Successful revocation of a refresh token returns HTTP 200 (RFC 7009)."""
    auth_header = create_basic_header(
        oauth_client.client_id, oauth_client.client_secret
    )
    response = client.post(
        "/oauth2/revoke",
        data={"token": encoded_jwt_refresh_token},
        headers=auth_header,
    )
    assert response.status_code == 200, response.data


def test_revoke_endpoint_invalid_client_id(
    client, oauth_client, encoded_jwt_refresh_token
):
    """Wrong client_id results in an authentication error."""
    auth_header = create_basic_header("wrong-client-id", oauth_client.client_secret)
    response = client.post(
        "/oauth2/revoke",
        data={"token": encoded_jwt_refresh_token},
        headers=auth_header,
    )
    # client authentication fails → 401 or 400
    assert response.status_code in (400, 401), response.data


def test_revoke_endpoint_invalid_client_secret(
    client, oauth_client, encoded_jwt_refresh_token
):
    """Wrong client_secret results in an authentication error."""
    auth_header = create_basic_header(oauth_client.client_id, "wrong-secret")
    response = client.post(
        "/oauth2/revoke",
        data={"token": encoded_jwt_refresh_token},
        headers=auth_header,
    )
    assert response.status_code in (400, 401), response.data


# ---------------------------------------------------------------------------
# Introspection endpoint HTTP tests
# ---------------------------------------------------------------------------


def test_introspect_endpoint_valid_token_returns_active(
    client, oauth_client, encoded_jwt
):
    """A valid JWT is introspected successfully and active=true is returned."""
    auth_header = create_basic_header(
        oauth_client.client_id, oauth_client.client_secret
    )
    response = client.post(
        "/oauth2/introspect",
        data={"token": encoded_jwt},
        headers=auth_header,
    )
    assert response.status_code == 200, response.json
    data = response.json
    assert data.get("active") is True
    assert "scope" in data or "token_type" in data


def test_introspect_endpoint_invalid_token_returns_inactive(client, oauth_client):
    """An invalid JWT results in active=false."""
    auth_header = create_basic_header(
        oauth_client.client_id, oauth_client.client_secret
    )
    response = client.post(
        "/oauth2/introspect",
        data={"token": "not.a.jwt.at.all"},
        headers=auth_header,
    )
    assert response.status_code == 200, response.json
    data = response.json
    assert data.get("active") is False
