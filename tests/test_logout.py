import urllib.parse
import urllib.request, urllib.parse, urllib.error
from fence.resources.storage.cdis_jwt import create_session_token
from fence.config import config

from fence.auth import build_redirect_url


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


def test_logout_itrust(client, db_session):
    r = client.get("/user/")
    r = client.get("/logout?next=https://some_site.com")
    assert r.status_code == 302
    parsed_url = urllib.parse.urlparse(r.location)
    raw_redirect = urllib.parse.parse_qs(parsed_url.query).get("AppReturnUrl")[0]
    redirect = urllib.parse.unquote(raw_redirect)
    assert redirect == "https://some_site.com"


def test_logout_fence(app, user_with_fence_provider, monkeypatch):
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
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

        r = client.get("/logout?next=https://some_site.com")
        assert r.status_code == 302
        assert r.location.startswith(other_fence_logout_url)

        parsed_url = urllib.parse.urlparse(r.location)
        raw_redirect = urllib.parse.parse_qs(parsed_url.query).get("next")[0]
        redirect = urllib.parse.unquote(raw_redirect)
        assert redirect == "https://some_site.com"
