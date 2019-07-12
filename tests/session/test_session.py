import time
import flask
from fence.resources.storage.cdis_jwt import create_session_token
from fence.jwt.token import generate_signed_access_token
from fence.config import config
from fence.models import User

from fence.jwt.keys import default_public_key
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

        client_cookies = [cookie.name for cookie in client.cookie_jar]
        assert not client_cookies


def test_session_cookie_creation_session_modified(app):
    # Test that when no session cookie exists, we create one that
    # doesn't have anything in it
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["username"] = "Captain Janeway"

        client_cookies = [cookie.name for cookie in client.cookie_jar]
        assert config["SESSION_COOKIE_NAME"] in client_cookies
        session_cookie = [
            cookie
            for cookie in client.cookie_jar
            if cookie.name == config["SESSION_COOKIE_NAME"]
        ]
        assert len(session_cookie) == 1
        assert session_cookie[0].value  # Make sure it's not empty


def test_valid_session(app):
    username = "Captain Janeway"

    test_session_jwt = create_session_token(
        app.keypairs[0], config.get("SESSION_TIMEOUT"), context={"username": username}
    )

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)
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
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)
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
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)
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
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)
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
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)
        with client.session_transaction() as session:
            session["username"] = username
            session.clear()
            assert session.get("username") != username
        client_cookies = [cookie.name for cookie in client.cookie_jar]
        assert config["SESSION_COOKIE_NAME"] not in client_cookies


def test_invalid_session_cookie(app):
    test_session_jwt = "garbage-string-to-represent-invalid-session-cookie"

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)
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

    test_session_jwt = create_session_token(
        keypair,
        config.get("SESSION_TIMEOUT"),
        context={"username": user.username, "provider": "google"},
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
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)
        client.set_cookie(
            "localhost", config["ACCESS_TOKEN_COOKIE_NAME"], test_access_jwt
        )

        response = client.get("/user")
        user_id = response.json.get("user_id") or response.json.get("sub")
        assert response.status_code == 200
        assert user_id == user.id


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
        client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)
        client.set_cookie(
            "localhost", config["ACCESS_TOKEN_COOKIE_NAME"], test_access_jwt
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
