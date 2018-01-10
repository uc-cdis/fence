from fence.resources.user.user_session import UserSessionInterface
from datetime import datetime
from fence.resources.storage.cdis_jwt import create_session_token
from requests import Request
from flask import Response
from fence.settings import SESSION_COOKIE_NAME

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
    from unittest.mock import call
except ImportError:
    from mock import MagicMock
    from mock import patch
    from mock import call


def test_session_cookie_creation(app):
    # Test that when no session cookie exists, we create one and
    # can access information from the JWT (like session_started time)
    with app.test_client() as client:
        with client.session_transaction() as session:
            assert session.get("session_started") is not None
        client_cookies = [cookie.name for cookie in client.cookie_jar]
        assert SESSION_COOKIE_NAME in client_cookies


def test_valid_session(app):
    username = "Captain Janeway"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT").seconds,
        username=username
    )

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)
        with client.session_transaction() as session:
            assert session["username"] == username


def test_valid_session_modified(app):
    username = "Captain Janeway"
    modified_username = "Captain Picard"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT").seconds,
        username=username
    )

    # Test that once the session is started, we have access to
    # the username
    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)
        with client.session_transaction() as session:

            assert session["username"] == username
            session["username"] = modified_username

        with client.session_transaction() as session:
            assert session["username"] == modified_username


def test_expired_session_lifetime(app):
    # make the start time be max lifetime ago (so it's expired)
    lifetime = app.config.get("SESSION_LIFETIME")
    now = int(datetime.utcnow().strftime("%s"))
    one_lifetime_ago = (now - lifetime.seconds)
    username = "Captain Janeway"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT").seconds,
        session_started=one_lifetime_ago,
        username=username
    )

    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)
        with client.session_transaction() as session:
            # make sure we don't have the username when opening
            # the session, since it has expired
            assert session.get("username") != username


def test_expired_session_timeout(app):
    # make the start time be one timeout in the past (so the
    # session is expired)
    max_inactivity = app.config.get("SESSION_TIMEOUT")
    now = int(datetime.utcnow().strftime("%s"))
    last_active = (now - max_inactivity.seconds)
    username = "Captain Janeway"

    # since we're timetraveling, we have to trick the JWT (since it relies
    # on the current time and this expiration to calculate
    # the actual expiration time). For testing, we'll "expire" it on creation
    jwt_expiration = 0
    test_session_jwt = create_session_token(
        app.keypairs[0],
        jwt_expiration,
        session_started=last_active,
        username=username
    )

    with app.test_client() as client:
        # manually set cookie for initial session
        client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)
        with client.session_transaction() as session:
            # make sure we don't have the username when opening
            # the session, since it has expired
            assert session.get("username") != username
