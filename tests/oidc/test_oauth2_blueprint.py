"""
Tests for fence/blueprints/oauth2.py

Covers:
- display_error() — returns query args as JSON
- authorize() auto_approve path — skips consent screen
- _handle_consent_confirmation() — user denies consent (confirm != 'yes')
- authorize() unauthenticated paths — DEFAULT_LOGIN_URL, unknown idp, fence/shib extras
- _get_auth_response_for_prompts() — prompt='none' with multiple values
- _get_authorize_error_response() — returns 302 with error params
- revoke_token() — BlacklistingInvalidTokenError returns 200
"""

from unittest.mock import patch, MagicMock
from urllib.parse import urlparse, parse_qs

import pytest

from fence.config import config
from fence.errors import BlacklistingInvalidTokenError
from fence.models import Client


# ---------------------------------------------------------------------------
# display_error
# ---------------------------------------------------------------------------


def test_display_error_returns_query_args_as_json(client):
    """
    GET /oauth2/errors?error=access_denied&error_description=foo
    returns those query params as a JSON object.
    Covers line 435.
    """
    response = client.get(
        "/oauth2/errors?error=access_denied&error_description=User+denied+access"
    )
    assert response.status_code == 200
    data = response.json
    assert data["error"] == "access_denied"
    assert "denied" in data["error_description"]


def test_display_error_with_no_params(client):
    """GET /oauth2/errors with no params returns an empty JSON object."""
    response = client.get("/oauth2/errors")
    assert response.status_code == 200
    assert response.json == {}


# ---------------------------------------------------------------------------
# auto_approve
# ---------------------------------------------------------------------------


def test_authorize_auto_approve_skips_consent_screen(
    client, oauth_test_client, oauth_client, db_session
):
    """
    When the OAuth client has auto_approve=True, the authorize endpoint
    issues a code without requiring a 'confirm' parameter.
    Covers line 141.
    """
    # Enable auto_approve on the DB client
    db_client = (
        db_session.query(Client).filter_by(client_id=oauth_client.client_id).first()
    )
    db_client.auto_approve = True
    db_session.commit()

    # Authorize without any 'confirm' param — should still get a code back
    auth_response = oauth_test_client.authorize(
        method="GET",
        data={"confirm": None},  # no confirm
        do_asserts=False,
    )
    # With auto_approve, the GET redirects straight to the redirect URI with a code
    location = auth_response.location
    assert location is not None
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    assert "code" in qs, f"Expected 'code' in redirect location, got: {location}"


# ---------------------------------------------------------------------------
# _handle_consent_confirmation — user denies
# ---------------------------------------------------------------------------


def test_handle_consent_confirmation_denied_returns_access_denied(oauth_test_client):
    """
    When the user responds with confirm != 'yes', the server responds with
    an access_denied error redirect.
    Covers line 169.
    """
    response = oauth_test_client.authorize(
        method="GET",
        data={"confirm": "no"},
        do_asserts=False,
    )
    location = response.location
    assert location is not None
    qs = parse_qs(urlparse(location).query)
    assert "error" in qs
    assert qs["error"][0] == "access_denied"


# ---------------------------------------------------------------------------
# _get_authorize_error_response — direct function test
# ---------------------------------------------------------------------------


def test_get_authorize_error_response_returns_302_with_error_params(app):
    """
    _get_authorize_error_response builds a 302 redirect containing the
    OAuth2 error params in the Location header.
    Covers lines 312-316.
    """
    from authlib.oauth2.rfc6749 import InvalidRequestError
    from fence.blueprints.oauth2 import _get_authorize_error_response

    error = InvalidRequestError(state="xyz")
    redirect_uri = "https://client.example.com/callback"

    with app.test_request_context("/"):
        response = _get_authorize_error_response(error, redirect_uri)

    assert response.status_code == 302
    location = response.headers["Location"]
    assert location.startswith(redirect_uri)
    qs = parse_qs(urlparse(location).query)
    assert "error" in qs
    assert qs["error"][0] == "invalid_request"


# ---------------------------------------------------------------------------
# _get_auth_response_for_prompts — 'none' with multiple prompts
# ---------------------------------------------------------------------------


def test_get_auth_response_for_prompts_none_combined_with_other_returns_error_redirect(
    app, oauth_user
):
    """
    _get_auth_response_for_prompts with prompt='none select_account' returns
    a 302 error redirect because 'none' cannot be combined with other values.
    Covers lines 216-222.
    """
    from fence.blueprints.oauth2 import _get_auth_response_for_prompts

    grant = MagicMock()
    grant.params = {
        "state": "teststate",
        "uri": "http://example.com",
        "redirect_uri": "https://client.example.com/callback",
    }
    user = MagicMock()
    client = MagicMock()

    with app.test_request_context("/"):
        response = _get_auth_response_for_prompts(
            "none select_account", grant, user, client, "openid"
        )

    assert response.status_code == 302
    location = response.headers["Location"]
    qs = parse_qs(urlparse(location).query)
    assert "error" in qs


def test_get_auth_response_for_prompts_none_unauthenticated_returns_access_denied(
    app, oauth_user
):
    """
    _get_auth_response_for_prompts with prompt='none' when get_current_user
    raises Unauthorized returns a 302 error redirect with access_denied.
    Covers lines 228-231.
    """
    from fence.blueprints.oauth2 import _get_auth_response_for_prompts
    from fence.errors import Unauthorized

    grant = MagicMock()
    grant.params = {
        "state": "teststate",
        "uri": "http://example.com",
        "redirect_uri": "https://client.example.com/callback",
    }
    user = MagicMock()
    client = MagicMock()

    with app.test_request_context("/"):
        with patch(
            "fence.blueprints.oauth2.get_current_user",
            side_effect=Unauthorized("not logged in"),
        ):
            response = _get_auth_response_for_prompts(
                "none", grant, user, client, "openid"
            )

    assert response.status_code == 302
    location = response.headers["Location"]
    qs = parse_qs(urlparse(location).query)
    assert "error" in qs
    assert qs["error"][0] == "access_denied"


# ---------------------------------------------------------------------------
# authorize() — unauthenticated paths
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def mock_auth_off(monkeypatch):
    """Disable MOCK_AUTH so get_current_user raises Unauthorized."""
    monkeypatch.setitem(config, "MOCK_AUTH", False)


def test_authorize_unauthenticated_uses_default_login_url_when_no_idp(
    client, mock_auth_off, monkeypatch
):
    """
    When no DEFAULT_LOGIN_IDP and 'default' not in ENABLED_IDENTITY_PROVIDERS,
    the authorize endpoint falls back to DEFAULT_LOGIN_URL.
    Covers line 91.
    """
    monkeypatch.setitem(config, "DEFAULT_LOGIN_IDP", None)
    monkeypatch.setitem(config, "ENABLED_IDENTITY_PROVIDERS", {})
    monkeypatch.setitem(
        config, "DEFAULT_LOGIN_URL", "https://fallback-login.example.com"
    )

    response = client.get(
        "/oauth2/authorize"
        "?client_id=test-client"
        "&response_type=code"
        "&scope=openid"
        "&redirect_uri=https://oauth-test-client.net"
    )
    # Should redirect to the fallback login URL
    assert response.status_code == 302
    location = response.headers["Location"]
    assert "fallback-login.example.com" in location


def test_authorize_unauthenticated_unknown_idp_raises_user_error(
    client, mock_auth_off, monkeypatch
):
    """
    When a specific idp is requested that is not in OPENID_CONNECT,
    a UserError (400) is raised.
    Covers lines 103-106.
    """
    monkeypatch.setitem(config, "DEFAULT_LOGIN_IDP", None)
    monkeypatch.setitem(config, "ENABLED_IDENTITY_PROVIDERS", {})
    monkeypatch.setitem(config, "DEFAULT_LOGIN_URL", None)
    monkeypatch.setitem(config, "OPENID_CONNECT", {"google": {}})

    response = client.get(
        "/oauth2/authorize"
        "?client_id=test-client"
        "&response_type=code"
        "&scope=openid"
        "&redirect_uri=https://oauth-test-client.net"
        "&idp=nonexistent_provider"
    )
    assert response.status_code == 400


def test_authorize_unauthenticated_fence_idp_adds_idp_param(
    client, mock_auth_off, monkeypatch
):
    """
    When idp='fence' and fence_idp is provided, the redirect to the login
    endpoint includes idp=<fence_idp> in the params.
    Covers lines 110-112.
    """
    monkeypatch.setitem(config, "DEFAULT_LOGIN_IDP", None)
    monkeypatch.setitem(config, "ENABLED_IDENTITY_PROVIDERS", {})
    monkeypatch.setitem(config, "DEFAULT_LOGIN_URL", None)
    monkeypatch.setitem(config, "OPENID_CONNECT", {"fence": {}})
    monkeypatch.setitem(config, "BASE_URL", config.get("BASE_URL", "http://localhost"))

    with patch("fence.blueprints.oauth2.get_idp_route_name", return_value="fence"):
        response = client.get(
            "/oauth2/authorize"
            "?client_id=test-client"
            "&response_type=code"
            "&scope=openid"
            "&redirect_uri=https://oauth-test-client.net"
            "&idp=fence"
            "&fence_idp=google"
        )

    assert response.status_code == 302
    location = response.headers["Location"]
    qs = parse_qs(urlparse(location).query)
    # The login URL should include the fence_idp as 'idp' param
    assert "idp" in qs
    assert qs["idp"][0] == "google"


def test_authorize_unauthenticated_shibboleth_idp_adds_shib_idp_param(
    client, mock_auth_off, monkeypatch
):
    """
    When idp='shibboleth' and shib_idp is provided, the redirect to the login
    endpoint includes shib_idp in the params.
    Covers line 114.
    """
    monkeypatch.setitem(config, "DEFAULT_LOGIN_IDP", None)
    monkeypatch.setitem(config, "ENABLED_IDENTITY_PROVIDERS", {})
    monkeypatch.setitem(config, "DEFAULT_LOGIN_URL", None)
    monkeypatch.setitem(config, "OPENID_CONNECT", {"shibboleth": {}})
    monkeypatch.setitem(config, "BASE_URL", config.get("BASE_URL", "http://localhost"))

    with patch("fence.blueprints.oauth2.get_idp_route_name", return_value="shibboleth"):
        response = client.get(
            "/oauth2/authorize"
            "?client_id=test-client"
            "&response_type=code"
            "&scope=openid"
            "&redirect_uri=https://oauth-test-client.net"
            "&idp=shibboleth"
            "&shib_idp=uchicago.edu"
        )

    assert response.status_code == 302
    location = response.headers["Location"]
    qs = parse_qs(urlparse(location).query)
    assert "shib_idp" in qs
    assert qs["shib_idp"][0] == "uchicago.edu"


# ---------------------------------------------------------------------------
# revoke_token — BlacklistingInvalidTokenError path
# ---------------------------------------------------------------------------


def test_revoke_token_blacklisting_invalid_token_returns_200(client, oauth_test_client):
    """
    When revoking a token that is already invalid, BlacklistingInvalidTokenError
    is caught and a 200 is returned (per RFC 7009).
    Covers lines 405-416.
    """
    # Get a real refresh token first
    oauth_test_client.authorize(data={"confirm": "yes"})
    oauth_test_client.token()
    refresh_token = oauth_test_client.token_response.refresh_token
    assert refresh_token, "Expected a refresh token"

    # Patch blacklist_encoded_token to raise BlacklistingInvalidTokenError
    with patch(
        "fence.blueprints.oauth2.blacklist_encoded_token",
        side_effect=BlacklistingInvalidTokenError("token invalid"),
    ):
        # Use form-encoded revoke (user-style, not client Basic-auth-style)
        # This follows the non-Basic-auth path in revoke_token
        # First, we need a valid Authorization header with the token itself
        # The user path requires Content-Type: application/x-www-form-urlencoded
        # and a 'token' field.
        # We also need a revoker token — use the refresh token as revoker too,
        # but mock validate_jwt to return valid claims.
        fake_claims = {"sub": "test", "pur": "refresh"}
        with patch(
            "fence.blueprints.oauth2.validate_jwt",
            return_value=fake_claims,
        ):
            with patch(
                "fence.blueprints.oauth2.authz_authorize",
                return_value=None,
            ):
                response = client.post(
                    "/oauth2/revoke",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": f"Bearer {refresh_token}",
                    },
                    data={"token": refresh_token},
                )

    assert response.status_code == 200
