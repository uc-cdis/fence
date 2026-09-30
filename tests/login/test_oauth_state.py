"""
The IdP login callback issues a Fence session for whatever identity an authorization
code resolves to, so the callback has to be bound to a login this browser actually
started. That binding is the OAuth `state` parameter.
"""

from urllib.parse import parse_qsl, urlparse

import pytest

from fence.config import config
from fence.resources.storage.cdis_jwt import create_session_token


IDP_LOGIN_ROUTE = "/login/google"
IDP_ROUTE = "/login/google/login"
STATE_SESSION_KEY = "oauth2_state_google"
ISSUED_STATE = "issued-state-value"


@pytest.fixture
def session_with_state(app, client):
    """Give the test client a session carrying an issued login state for Google."""

    def seed(state=ISSUED_STATE):
        session_jwt = create_session_token(
            app.keypairs[0],
            config.get("SESSION_TIMEOUT"),
            context={STATE_SESSION_KEY: state},
        )
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            session_jwt,
            httponly=True,
            samesite="Lax",
        )

    return seed


@pytest.fixture(autouse=True)
def real_google_login(monkeypatch):
    """Exercise the real callback rather than the mock-login shortcut."""
    monkeypatch.setitem(config, "MOCK_GOOGLE_AUTH", False)
    monkeypatch.setitem(
        config["OPENID_CONNECT"].setdefault("google", {}), "mock", False
    )


def test_callback_rejects_code_with_no_state(client, session_with_state):
    """A callback carrying only a code is refused."""
    session_with_state()

    response = client.get(IDP_ROUTE + "?code=ATTACKER_CODE")

    assert response.status_code == 401


def test_callback_rejects_forged_state(client, session_with_state):
    """A callback whose state was not issued by this session is refused."""
    session_with_state()

    response = client.get(IDP_ROUTE + "?code=ATTACKER_CODE&state=attacker-chosen")

    assert response.status_code == 401


def test_callback_rejects_state_with_no_session(client):
    """A callback arriving with no login in progress is refused."""
    response = client.get(IDP_ROUTE + f"?code=ATTACKER_CODE&state={ISSUED_STATE}")

    assert response.status_code == 401


def test_callback_accepts_issued_state(client, session_with_state):
    """
    A callback carrying the state this session was issued gets past the state check.

    The request then fails further along because the code is not redeemable here, so
    this asserts only that the state check is not what rejected it.
    """
    session_with_state()

    response = client.get(IDP_ROUTE + f"?code=ATTACKER_CODE&state={ISSUED_STATE}")

    assert response.status_code != 401


def test_issued_state_is_single_use(client, session_with_state):
    """Replaying a state that was already consumed is refused."""
    session_with_state()

    first = client.get(IDP_ROUTE + f"?code=ATTACKER_CODE&state={ISSUED_STATE}")
    second = client.get(IDP_ROUTE + f"?code=ATTACKER_CODE&state={ISSUED_STATE}")

    assert first.status_code != 401
    assert second.status_code == 401


def test_state_issued_by_login_is_accepted_by_callback(app, client, monkeypatch):
    """
    A state minted by the login endpoint is accepted by the callback.

    Covers the whole hop rather than a seeded session: the login response has to
    persist the state in a session cookie for a caller that arrived without one, and
    the callback has to read it back out.
    """
    monkeypatch.setattr(
        app.google_client, "get_auth_url", lambda: "https://idp.example.com/authorize"
    )

    login_response = client.get(IDP_LOGIN_ROUTE + "?redirect=" + config["BASE_URL"])
    assert login_response.status_code == 302
    issued_state = dict(parse_qsl(urlparse(login_response.headers["Location"]).query))[
        "state"
    ]

    response = client.get(IDP_ROUTE + f"?code=ATTACKER_CODE&state={issued_state}")

    assert response.status_code != 401


def test_error_branch_requires_state(client, session_with_state):
    """
    The IdP-error branch is also behind the state check.

    That branch redirects using a session value and runs before the code exchange, so
    leaving it unguarded would keep an unauthenticated redirect primitive open.
    """
    session_with_state()

    response = client.get(IDP_ROUTE + "?error=access_denied")

    assert response.status_code == 401
