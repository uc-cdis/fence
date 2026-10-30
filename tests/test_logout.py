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
        "fence.allowed_login_redirects",
        return_value={"test-url.com", "cognito.example.com"},
    ), mock.patch(
        "fence.auth.allowed_login_redirects",
        return_value={"test-url.com", "cognito.example.com"},
    ), mock.patch(
        "requests.get"
    ) as mock_get:
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_well_known
        mock_get.return_value = mock_resp

        r = client.get("/logout?next={}".format(redirect))
        assert r.status_code == 302
        assert "https://cognito.example.com/logout" in r.location


def test_logout_cognito_cognito_not_in_allowed_login_redirect(client, db_session):
    """
    Test /logout endpoint without correct cognito domain in allow list
    """
    redirect = "https://test-url.com"
    mock_well_known = {"end_session_endpoint": "https://cognito.example.com/logout"}
    r = client.get("/user/")
    with client.session_transaction() as session:
        session["provider"] = "cognito"
    with mock.patch(
        "fence.allowed_login_redirects",
        return_value={"test-url.com", "not.cognito.example.com"},
    ), mock.patch(
        "fence.auth.allowed_login_redirects",
        return_value={"test-url.com", "not.cognito.example.com"},
    ), mock.patch(
        "requests.get"
    ) as mock_get:
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_well_known
        mock_get.return_value = mock_resp

        r = client.get("/logout?next={}".format(redirect))
        assert r.status_code == 302
        assert "https://cognito.example.com/logout" not in r.location
        assert r.location == redirect


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


def _query(url):
    """Return the query parameters of a URL as a dict of lists"""
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


@pytest.fixture
def generic_idps(monkeypatch):
    """
    Add generic OIDC IdPs to the config, with and without `logout_url` and
    related settings.
    """
    openid_connect = dict(config["OPENID_CONNECT"])
    openid_connect.update(
        {
            "generic_idp_a": {
                "client_id": "client_a",
                "logout_url": "https://idp-a.example.com/logout",
            },
            # mixed-case key; the session provider is the lowercased key
            "Generic_IdP_B": {
                "client_id": "client_b",
                "logout_url": "https://idp-b.example.com/oidc/logout",
            },
            "generic_idp_query": {
                "client_id": "client_q",
                "logout_url": "https://idp-q.example.com/logout?foo=bar",
            },
            "generic_idp_own_client_id": {
                "client_id": "client_c",
                "logout_url": "https://idp-c.example.com/logout?client_id=other",
            },
            "generic_idp_no_client_id": {
                "logout_url": "https://idp-n.example.com/logout",
            },
            "generic_idp_param_name": {
                "client_id": "client_p",
                "logout_url": "https://idp-p.example.com/logout",
                "logout_redirect_param_name": "logout_uri",
            },
            "generic_idp_no_logout": {"client_id": "client_x"},
        }
    )
    monkeypatch.setitem(config, "OPENID_CONNECT", openid_connect)


def _logout(client, provider, redirect):
    """Log out a session of `provider` with `next=redirect`"""
    client.get("/user/")
    with client.session_transaction() as session:
        session["provider"] = provider
    with mock.patch("fence.allowed_login_redirects", return_value={"test-url.com"}):
        return client.get("/logout?next={}".format(urllib.parse.quote_plus(redirect)))


@pytest.mark.parametrize(
    "provider, logout_url, client_id",
    [
        ("generic_idp_a", "https://idp-a.example.com/logout", "client_a"),
        ("generic_idp_b", "https://idp-b.example.com/oidc/logout", "client_b"),
    ],
)
def test_logout_generic_idp_logout_url(
    client, db_session, generic_idps, provider, logout_url, client_id
):
    """
    Test /logout redirects to the `logout_url` of the session's IdP with
    `client_id` and `post_logout_redirect_uri` added (OpenID Connect
    RP-Initiated Logout)
    """
    redirect = "https://test-url.com/some/path?a=b&c=d"
    r = _logout(client, provider, redirect)
    assert r.status_code == 302
    assert r.location.split("?")[0] == logout_url
    assert _query(r.location) == {
        "client_id": [client_id],
        "post_logout_redirect_uri": [redirect],
    }


def test_logout_generic_idp_logout_url_with_query(client, db_session, generic_idps):
    """
    Test the parameters are added to a `logout_url` that has a query string
    """
    redirect = "https://test-url.com"
    r = _logout(client, "generic_idp_query", redirect)
    assert r.status_code == 302
    assert r.location.startswith("https://idp-q.example.com/logout?")
    assert _query(r.location) == {
        "foo": ["bar"],
        "client_id": ["client_q"],
        "post_logout_redirect_uri": [redirect],
    }


def test_logout_generic_idp_logout_url_with_client_id(client, db_session, generic_idps):
    """
    Test a `client_id` in `logout_url` is kept and not duplicated
    """
    redirect = "https://test-url.com"
    r = _logout(client, "generic_idp_own_client_id", redirect)
    assert r.status_code == 302
    assert _query(r.location) == {
        "client_id": ["other"],
        "post_logout_redirect_uri": [redirect],
    }


def test_logout_generic_idp_without_client_id(client, db_session, generic_idps):
    """
    Test only the redirect parameter is added when the IdP has no `client_id`
    """
    redirect = "https://test-url.com"
    r = _logout(client, "generic_idp_no_client_id", redirect)
    assert r.status_code == 302
    assert _query(r.location) == {"post_logout_redirect_uri": [redirect]}


def test_logout_generic_idp_logout_redirect_param_name(
    client, db_session, generic_idps
):
    """
    Test `logout_redirect_param_name` sets the name of the redirect parameter
    """
    redirect = "https://test-url.com"
    r = _logout(client, "generic_idp_param_name", redirect)
    assert r.status_code == 302
    assert r.location.startswith("https://idp-p.example.com/logout?")
    assert _query(r.location) == {
        "client_id": ["client_p"],
        "logout_uri": [redirect],
    }


def test_logout_generic_idp_without_logout_url(client, db_session, generic_idps):
    """
    Test /logout redirects straight to next when the session's IdP has no
    `logout_url`
    """
    redirect = "https://test-url.com"
    r = _logout(client, "generic_idp_no_logout", redirect)
    assert r.status_code == 302
    assert r.location == redirect


def test_logout_generic_idp_logout_url_error(client, db_session, generic_idps):
    """
    Test /logout still logs out of Gen3 and redirects straight to next when
    building the IdP logout URL fails
    """
    redirect = "https://test-url.com"
    with mock.patch("fence.auth.build_idp_logout_url", side_effect=Exception("boom")):
        r = _logout(client, "generic_idp_a", redirect)
    assert r.status_code == 302
    assert r.location == redirect


def test_logout_cognito_ignores_logout_url(client, db_session, monkeypatch):
    """
    Test the built-in cognito IdP keeps its discovery-based logout when a
    `logout_url` is set
    """
    redirect = "https://test-url.com"
    openid_connect = dict(config["OPENID_CONNECT"])
    openid_connect["cognito"] = dict(
        openid_connect.get("cognito", {}),
        logout_url="https://other.example.com/logout",
    )
    monkeypatch.setitem(config, "OPENID_CONNECT", openid_connect)
    client.get("/user/")
    with client.session_transaction() as session:
        session["provider"] = "cognito"
    with mock.patch(
        "fence.allowed_login_redirects",
        return_value={"test-url.com", "cognito.example.com"},
    ), mock.patch(
        "fence.auth.allowed_login_redirects",
        return_value={"test-url.com", "cognito.example.com"},
    ), mock.patch(
        "requests.get"
    ) as mock_get:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "end_session_endpoint": "https://cognito.example.com/logout"
        }
        mock_get.return_value = mock_resp
        r = client.get("/logout?next={}".format(redirect))
    assert r.status_code == 302
    assert r.location.startswith("https://cognito.example.com/logout?")
    assert _query(r.location)["logout_uri"] == [redirect]
