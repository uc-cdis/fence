import time
import flask
from fence.resources.storage.cdis_jwt import create_session_token
from fence.jwt.token import generate_signed_access_token
from fence.config import config
from fence.models import User

from fence.jwt.keys import default_public_key, Keypair
from fence.jwt.validate import validate_jwt

from unittest.mock import MagicMock, patch, call

import pytest


@pytest.fixture(autouse=True)
def mock_arborist(mock_arborist_requests):
    mock_arborist_requests()


def test_session_cookie_creation(app):
    # Test that when we don't modify the session, a
    # session cookie does not get created
    with app.test_client() as client:
        with client.session_transaction():
            pass
        client_cookies = client.get_cookie(config["SESSION_COOKIE_NAME"])
        assert not client_cookies


def test_session_cookie_creation_session_modified(app):
    # Test that when no session cookie exists, we create one that
    # doesn't have anything in it
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["username"] = "Captain Janeway"

        session_cookie = client.get_cookie(config["SESSION_COOKIE_NAME"])
        assert session_cookie
        assert session_cookie.value  # Make sure it's not empty


def test_valid_session(app):
    username = "Captain Janeway"

    test_session_jwt = create_session_token(
        app.keypairs[0], config.get("SESSION_TIMEOUT"), context={"username": username}
    )

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        # domain is set to localhost be default
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        with client.session_transaction() as session:
            assert session["username"] == username


def test_valid_session_modified(app):
    username = "Captain Janeway"
    modified_username = "Captain Picard"

    test_session_jwt = create_session_token(
        app.keypairs[0], config.get("SESSION_TIMEOUT"), context={"username": username}
    )

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        with client.session_transaction() as session:
            assert session["username"] == username
            session["username"] = modified_username

        with client.session_transaction() as session:
            assert session["username"] == modified_username


def test_expired_session_lifetime(app):
    # make the start time be max lifetime ago (so it's expired)
    lifetime = config.get("SESSION_LIFETIME")
    now = int(time.time())
    one_lifetime_ago = now - lifetime
    username = "Captain Janeway"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context=dict(session_started=one_lifetime_ago, username=username),
    )

    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        with client.session_transaction() as session:
            # make sure we don't have the username when opening
            # the session, since it has expired
            assert session.get("username") != username


def test_expired_session_timeout(app):
    # make the start time be one timeout in the past (so the
    # session is expired)
    max_inactivity = config.get("SESSION_TIMEOUT")
    now = int(time.time())
    last_active = now - max_inactivity
    username = "Captain Janeway"

    # since we're timetraveling, we have to trick the JWT (since it relies
    # on the current time and this expiration to calculate
    # the actual expiration time). For testing, we'll "expire" it on creation
    jwt_expiration = 0
    test_session_jwt = create_session_token(
        app.keypairs[0],
        jwt_expiration,
        context=dict(session_started=last_active, username=username),
    )
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        with client.session_transaction() as session:
            # make sure we don't have the username when opening
            # the session, since it has expired
            assert session.get("username") != username


def test_session_cleared(app):
    username = "Captain Janeway"

    test_session_jwt = create_session_token(
        app.keypairs[0], config.get("SESSION_TIMEOUT"), context=dict(username=username)
    )

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie(
            key=config["SESSION_COOKIE_NAME"],
            value=test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        with client.session_transaction() as session:
            session["username"] = username
            session.clear()
            assert session.get("username") != username
        client_cookie = client.get_cookie(config["SESSION_COOKIE_NAME"])
        assert not client_cookie


def test_invalid_session_cookie(app):
    test_session_jwt = "garbage-string-to-represent-invalid-session-cookie"

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        with client.session_transaction() as session:
            # main test is that we haven't raised an exception by this point

            # for utmost clarity, make sure that no username
            # exists in the session yet
            assert not session.get("username")


def test_valid_session_valid_access_token(
    app, db_session, test_user_a, test_user_b, monkeypatch
):
    monkeypatch.setitem(config, "MOCK_AUTH", False)
    user = db_session.query(User).filter_by(id=test_user_a["user_id"]).first()
    keypair = app.keypairs[0]

    # without user_id the session token's "sub" is empty, and the access token below
    # would be rejected as belonging to a different subject
    test_session_jwt = create_session_token(
        keypair,
        config.get("SESSION_TIMEOUT"),
        context={"username": user.username, "user_id": user.id, "provider": "google"},
    )

    test_access_jwt = generate_signed_access_token(
        kid=keypair.kid,
        private_key=keypair.private_key,
        user=user,
        expires_in=config["ACCESS_TOKEN_EXPIRES_IN"],
        scopes=["openid", "user"],
        iss=config.get("BASE_URL"),
        forced_exp_time=None,
        client_id=None,
        linked_google_email=None,
    ).token

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        client.set_cookie(
            config["ACCESS_TOKEN_COOKIE_NAME"],
            test_access_jwt,
            httponly=True,
            samesite="Lax",
        )

        response = client.get("/user")
        user_id = response.json.get("user_id") or response.json.get("sub")
        assert response.status_code == 200
        assert user_id == user.id
        # the request's access token is usable and nowhere near expiring
        assert "access_token" not in _get_cookies_from_response(response)


def test_valid_session_valid_access_token_diff_user(
    app, test_user_a, test_user_b, db_session, monkeypatch
):
    """
    Test the case where a valid access token is in a cookie, but it's for a
    different user than the one logged in. Make sure that a new access token
    is created for the logged in user and the response doesn't contain info
    for the non-logged in user.
    """
    monkeypatch.setitem(config, "MOCK_AUTH", False)
    user = db_session.query(User).filter_by(id=test_user_a["user_id"]).first()
    keypair = app.keypairs[0]

    test_session_jwt = create_session_token(
        keypair,
        config.get("SESSION_TIMEOUT"),
        context={"username": user.username, "provider": "google"},
    )

    # different user's access token
    other_user = db_session.query(User).filter_by(id=test_user_b["user_id"]).first()
    test_access_jwt = generate_signed_access_token(
        kid=keypair.kid,
        private_key=keypair.private_key,
        user=other_user,
        expires_in=config["ACCESS_TOKEN_EXPIRES_IN"],
        scopes=["openid", "user"],
        iss=config.get("BASE_URL"),
    ).token

    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        client.set_cookie(
            config["ACCESS_TOKEN_COOKIE_NAME"],
            test_access_jwt,
            httponly=True,
            samesite="Lax",
        )

        response = client.get("/user")
        cookies = _get_cookies_from_response(response)

        # either there's a new access_token in the response headers or the
        # previously set access token been changed
        access_token = (
            cookies.get("access_token", {}).get("access_token") or test_access_jwt
        )

        valid_access_token = validate_jwt(access_token, purpose="access")
        assert response.status_code == 200
        response_user_id = response.json.get("user_id") or response.json.get("sub")
        assert response_user_id == test_user_a["user_id"]

        user_id = valid_access_token.get("user_id") or valid_access_token.get("sub")
        assert test_user_a["user_id"] == int(user_id)


@pytest.mark.parametrize(
    "expires_in,threshold_config,expect_renewal",
    [
        # inside the renewal window
        (60, 300, True),
        # renewal disabled
        (60, 0, False),
        # freshly issued token
        (config["ACCESS_TOKEN_EXPIRES_IN"], 300, False),
    ],
)
def test_access_token_renewal_threshold(
    app,
    db_session,
    test_user_a,
    monkeypatch,
    expires_in,
    threshold_config,
    expect_renewal,
):
    """An unexpired access token is replaced only when it is within the threshold."""
    monkeypatch.setitem(config, "MOCK_AUTH", False)
    monkeypatch.setitem(config, "ACCESS_TOKEN_RENEWAL_THRESHOLD", threshold_config)
    monkeypatch.setitem(config, "RENEW_ACCESS_TOKEN_BEFORE_EXPIRATION", False)

    user = db_session.query(User).filter_by(id=test_user_a["user_id"]).first()
    keypair = app.keypairs[0]

    # user_id is what ends up in the session token's "sub", which the access token
    # cookie is checked against
    test_session_jwt = create_session_token(
        keypair,
        config.get("SESSION_TIMEOUT"),
        context={"username": user.username, "user_id": user.id, "provider": "google"},
    )
    test_access_jwt = generate_signed_access_token(
        kid=keypair.kid,
        private_key=keypair.private_key,
        user=user,
        expires_in=expires_in,
        scopes=["openid", "user"],
        iss=config.get("BASE_URL"),
    ).token

    with app.test_client() as client:
        client.set_cookie(
            config["SESSION_COOKIE_NAME"],
            test_session_jwt,
            httponly=True,
            samesite="Lax",
        )
        client.set_cookie(
            config["ACCESS_TOKEN_COOKIE_NAME"],
            test_access_jwt,
            httponly=True,
            samesite="Lax",
        )

        response = client.get("/user")
        assert response.status_code == 200

        new_access_token = _get_cookies_from_response(response).get("access_token", {})
        assert bool(new_access_token) == expect_renewal

        if expect_renewal:
            original_exp = validate_jwt(test_access_jwt, purpose="access")["exp"]
            renewed = validate_jwt(new_access_token["access_token"], purpose="access")
            assert renewed["exp"] > original_exp


@pytest.mark.parametrize(
    "session_state,access_token_state,renew_config,threshold_config,expect_created",
    [
        # no usable access token in the request
        ("logged_in", "missing", False, 300, True),
        ("logged_in", "expired", False, 300, True),
        ("logged_in", "malformed", False, 300, True),
        ("logged_in", "other_user", False, 300, True),
        # inside and outside the renewal window
        ("logged_in", "near_expiry", False, 300, True),
        ("logged_in", "near_expiry", False, 0, False),
        ("logged_in", "fresh", False, 300, False),
        # RENEW_ACCESS_TOKEN_BEFORE_EXPIRATION short-circuits both token checks
        ("logged_in", "fresh", True, 300, True),
        ("logged_in", "fresh", True, 0, True),
        # nobody is logged in
        ("anonymous", "missing", True, 300, False),
        ("no_session_cookie", "missing", True, 300, False),
    ],
)
def test_create_access_token_cookie_called(
    app,
    db_session,
    test_user_a,
    test_user_b,
    monkeypatch,
    session_state,
    access_token_state,
    renew_config,
    threshold_config,
    expect_created,
):
    """
    The access token cookie is created only for a logged in user, and only when renewal
    is forced, the request's access token is unusable, or it is near expiration.
    """
    monkeypatch.setitem(config, "MOCK_AUTH", False)
    monkeypatch.setitem(config, "ACCESS_TOKEN_RENEWAL_THRESHOLD", threshold_config)
    monkeypatch.setitem(config, "RENEW_ACCESS_TOKEN_BEFORE_EXPIRATION", renew_config)

    keypair = app.keypairs[0]
    user = db_session.query(User).filter_by(id=test_user_a["user_id"]).first()
    other_user = db_session.query(User).filter_by(id=test_user_b["user_id"]).first()

    session_jwt = _session_token_for_state(keypair, session_state, user)
    access_jwt = _access_token_for_state(keypair, access_token_state, user, other_user)

    with app.test_client() as client:
        if session_jwt:
            client.set_cookie(
                config["SESSION_COOKIE_NAME"],
                session_jwt,
                httponly=True,
                samesite="Lax",
            )
        if access_jwt:
            client.set_cookie(
                config["ACCESS_TOKEN_COOKIE_NAME"],
                access_jwt,
                httponly=True,
                samesite="Lax",
            )

        with patch(
            "fence.resources.user.user_session._create_access_token_cookie"
        ) as create_access_token_cookie:
            response = client.get("/user")

    assert response.status_code == (200 if session_state == "logged_in" else 401)
    assert create_access_token_cookie.called == expect_created


def _session_token_for_state(keypair: Keypair, state: str, user: User) -> str | None:
    """
    Build the session cookie value for a scenario.

    Args:
        keypair (fence.jwt.keys.Keypair): keypair to sign the token with
        state (str): "logged_in", "anonymous" or "no_session_cookie"
        user (fence.models.User): the user to log in

    Returns:
        str | None: encoded session token, or None to send no session cookie
    """
    if state == "no_session_cookie":
        return None

    contexts = {
        # the session token's "sub" comes from user_id, and an access token whose
        # subject doesn't match the session's is treated as invalid
        "logged_in": {
            "username": user.username,
            "user_id": user.id,
            "provider": "google",
        },
        "anonymous": {},
    }

    return create_session_token(
        keypair, config.get("SESSION_TIMEOUT"), context=contexts[state]
    )


def _access_token_for_state(
    keypair: Keypair, state: str, user: User, other_user: User
) -> str | None:
    """
    Build the access token cookie value for a scenario.

    Args:
        keypair (fence.jwt.keys.Keypair): keypair to sign the token with
        state (str): "missing", "fresh", "near_expiry", "expired", "malformed" or
            "other_user"
        user (fence.models.User): the logged in user
        other_user (fence.models.User): a user who is not logged in

    Returns:
        str | None: encoded access token, or None to send no access token cookie
    """
    if state == "missing":
        return None

    if state == "malformed":
        return "garbage-string-to-represent-an-invalid-access-token"

    if state == "fresh" or state == "other_user":
        expires_in = config["ACCESS_TOKEN_EXPIRES_IN"]
    elif state == "near_expiry":
        expires_in = 60
    elif state == "expired":
        expires_in = -10
    else:
        raise ValueError(f"unknown access token state: {state}")

    return generate_signed_access_token(
        kid=keypair.kid,
        private_key=keypair.private_key,
        user=other_user if state == "other_user" else user,
        expires_in=expires_in,
        scopes=["openid", "user"],
        iss=config.get("BASE_URL"),
    ).token


def _get_cookies_from_response(response):
    raw_cookies = [
        header[1] for header in response.headers.items() if header[0] == "Set-Cookie"
    ]
    cookies = {}
    for cookie in raw_cookies:
        cookie_items = [item.strip() for item in cookie.split(";")]
        cookie_name = cookie_items[0].split("=")[0]
        cookie_info = {
            item.split("=")[0]: item.split("=")[1]
            for item in cookie_items
            if len(item.split("=")) > 1
        }
        cookie_more_info = {
            item: None for item in cookie_items if len(item.split("=")) == 1
        }
        cookie_info.update(cookie_more_info)
        cookies[cookie_name] = cookie_info
    return cookies
