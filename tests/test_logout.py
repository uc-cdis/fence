import mock
import urllib.request, urllib.parse, urllib.error
from unittest.mock import MagicMock

import flask
import pytest
import requests

from fence.auth import build_redirect_url
from fence.config import config
from fence.resources.storage.cdis_jwt import create_session_token


@pytest.fixture(autouse=True)
def mock_arborist(mock_arborist_requests):
    mock_arborist_requests()


def test_redirect_url():
    assert build_redirect_url("", "/") == "/"
    assert build_redirect_url("host.domain", "/fred") == "https://host.domain/fred"
    assert (
        build_redirect_url("http://host.domain", "/a/b/c") == "http://host.domain/a/b/c"
    )


def test_logout_if_anonymous(app, client, monkeypatch):
    """Logout when anonymous should display no error and successfully
    redirect user"""
    monkeypatch.setitem(config, "MOCK_AUTH", False)
    r = client.get("/logout")
    assert r.status_code == 302


def test_logout(client, db_session):
    # login mocked user
    r = client.get("/user/")
    r = client.get("/logout")
    assert r.status_code == 302


def test_logout_invalid_redirect(client, db_session):
    r = client.get("/user/")
    r = client.get("/logout?next=https://bogus.website")
    assert r.status_code == 400


def test_logout_itrust(client, db_session):
    redirect = "https://some_site.com"
    with mock.patch("fence.allowed_login_redirects", return_value={"some_site.com"}):
        r = client.get("/user/")
        r = client.get("/logout?next={}".format(redirect))
        assert r.status_code == 302
        parsed_url = urllib.parse.urlparse(r.location)
        raw_redirect = urllib.parse.parse_qs(parsed_url.query).get("AppReturnUrl")[0]
        result_redirect = urllib.parse.unquote(raw_redirect)
        assert result_redirect == redirect


def test_logout_fence(app, client, user_with_fence_provider, monkeypatch):
    other_fence_logout_url = "https://test-url.com"
    monkeypatch.setitem(config, "MOCK_AUTH", False)
    monkeypatch.setitem(config, "SHIBBOLETH_HEADER", None)
    monkeypatch.setitem(
        config, "OPENID_CONNECT", {"fence": {"api_base_url": other_fence_logout_url}}
    )

    username = "test-fence-provider"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={"username": username, "provider": "fence"},
    )

    # Test that once the session is started, we have access to
    # the username
    redirect = "https://some_site.com"
    # fence will reject unexpected redirect URLs, so we patch the validator to consider
    # this redirect valid
    with mock.patch("fence.allowed_login_redirects", return_value={"some_site.com"}):
        # manually set cookie for initial session
        client.set_cookie(
            key=config["SESSION_COOKIE_NAME"],
            value=test_session_jwt,
            # domain is used in client.get_cookie, it defaults to locahost anyway
            domain="localhost",
            httponly=True,
            samesite="Lax",
        )

        r = client.get("/logout?next={}".format(redirect))
        assert r.status_code == 302
        assert r.location.startswith(other_fence_logout_url)

        parsed_url = urllib.parse.urlparse(r.location)
        result_redirect = urllib.parse.parse_qs(parsed_url.query).get("next")[0]
        assert result_redirect == redirect


def test_logout_cognito(client, db_session):
    """
    Test /logout endpoint successfully redirect for logout with cognito
    """
    redirect = "https://test-url.com"
    mock_well_known = {"end_session_endpoint": "https://cognito.example.com/logout"}
    r = client.get("/user/")
    with client.session_transaction() as session:
        session["provider"] = "cognito"
    with mock.patch(
        "fence.allowed_login_redirects", return_value={"test-url.com"}
    ), mock.patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_well_known
        mock_get.return_value = mock_resp

        r = client.get("/logout?next={}".format(redirect))
        assert r.status_code == 302
        assert "https://cognito.example.com/logout" in r.location


def test_logout_cognito_http_error_next_url_fallback(client, db_session):
    """
    Test /logout endpoint falls back to next_url when cognito well-known returns http error
    """
    redirect = "https://test-url.com"
    r = client.get("/user/")
    with client.session_transaction() as session:
        session["provider"] = "cognito"
    with mock.patch(
        "fence.allowed_login_redirects", return_value={"test-url.com"}
    ), mock.patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=MagicMock(status_code=500)
        )
        mock_get.return_value = mock_resp
        r = client.get("/logout?next={}".format(redirect))
        assert r.status_code == 302
        assert "cognito" not in r.location
        assert r.location == redirect


def test_logout_cognito_connection_error_next_url_fallback(client, db_session):
    """
    Test /logout endpoint falls back to next_url when cognito well-known has connection error
    """
    redirect = "https://test-url.com"
    r = client.get("/user/")
    with client.session_transaction() as session:
        session["provider"] = "cognito"
    with mock.patch(
        "fence.allowed_login_redirects", return_value={"test-url.com"}
    ), mock.patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.ConnectionError(
            "Cognito Connection Error"
        )
        mock_get.return_value = mock_resp
        r = client.get("/logout?next={}".format(redirect))
        assert r.status_code == 302
        assert "cognito" not in r.location
        assert r.location == redirect
