from unittest import mock
import flask
import pytest
from fence.auth import (
    _identify_user_and_update_database,
    login_user_or_require_registration,
    logout,
)
from fence.models import User, IdentityProvider
import time
from datetime import datetime
from fence.config import config
from fence.errors import Unauthorized


@mock.patch("fence.auth.get_ip_information_string")
def test_login_user_already_in_db(get_ip_information_string_mock, db_session):
    """
    Test that if a user is already in the database and logs in, the session will contain
    the user's information (including additional information that may have been provided
    during the login like email and id_from_idp)
    """
    email = "testuser@gmail.com"
    provider = "Test Provider"
    id_from_idp = "Provider_ID_0001"

    test_user = User(username=email, is_admin=False)
    db_session.add(test_user)
    db_session.commit()
    user_id = str(test_user.id)
    assert not test_user.email
    assert not test_user.id_from_idp

    is_logged_in = login_user_or_require_registration(
        email, provider, email=email, id_from_idp=id_from_idp
    )
    assert is_logged_in

    assert test_user.identity_provider.name == provider
    assert test_user.id_from_idp == id_from_idp
    assert test_user.email == email
    assert flask.session["username"] == email
    assert flask.session["provider"] == provider
    assert flask.session["user_id"] == user_id
    assert flask.g.user == test_user

    assert get_ip_information_string_mock.called


def test_login_failure_for_user_already_in_db_but_inactive(db_session):
    """
    Test that if a user is already in the database, but is set to user.active == False,
     and logs in, the login returns an Unauthorized error.
    """
    email = "testuser@gmail.com"
    provider = "Test Provider"
    id_from_idp = "Provider_ID_0001"

    test_user = User(username=email, is_admin=False, active=False)
    db_session.add(test_user)
    db_session.commit()
    with pytest.raises(
        Unauthorized, match="User is known but not authorized/activated in the system"
    ):
        login_user_or_require_registration(
            email, provider, email=email, id_from_idp=id_from_idp
        )


def test_login_user_with_idp_already_in_db(db_session):
    """
    Test that if a user is already in the database, has identity_provider
    configured, and logs in, the session will contain the user's information.
    """
    email = "testuser@gmail.com"
    provider = "Test Provider"
    id_from_idp = "Provider_ID_0001"

    test_user = User(
        username=email, email=email, id_from_idp=id_from_idp, is_admin=False
    )
    test_idp = IdentityProvider(name=provider)
    test_user.identity_provider = test_idp

    db_session.add(test_user)
    db_session.commit()
    user_id = str(test_user.id)

    is_logged_in = login_user_or_require_registration(
        email, provider, email=email, id_from_idp=id_from_idp
    )
    assert is_logged_in

    assert test_user.identity_provider.name == provider
    assert test_user.id_from_idp == id_from_idp
    assert test_user.email == email
    assert flask.session["username"] == email
    assert flask.session["provider"] == provider
    assert flask.session["user_id"] == user_id
    assert flask.g.user == test_user


@pytest.mark.parametrize(
    "username",
    [
        "example@gmail.com",
        "example@gmail.org",
        "example@subdomain.gmail.com",
        "example@subdomain.gmail.org",
        "example.com.org.gmail@subdomain.gmail.org",
        "ASDALKSJD(*)!&@#(*&^DFGA@gmail.com",
        "badactor@example.com",
    ],
)
def test_login_user_with_denied_username(db_session, username, monkeypatch):
    """
    Test that usernames that are configured to be denied are actually denied
    """
    email = "example@example.com"
    provider = "Test Provider"
    id_from_idp = "Provider_ID_0001"

    deny_regex = "badactor@example.com|(.*@.*(126|163|aol|bk|foxmail|gmail|hotmail|icloud|inbox|live|mail|mailinator|outlook|proton|qq|rambler|sina|yeah|yahoo|yandex).*)"

    monkeypatch.setitem(config, "GLOBAL_USERNAME_DENY_REGEX", deny_regex)
    test_user = User(
        username=username,
        email=email,
        id_from_idp=id_from_idp,
        is_admin=False,
    )
    test_idp = IdentityProvider(name=provider)
    test_user.identity_provider = test_idp

    db_session.add(test_user)
    db_session.commit()

    with pytest.raises(Exception):
        _identify_user_and_update_database(
            username, provider, email=email, id_from_idp=id_from_idp
        )


@mock.patch("fence.auth.get_ip_information_string")
def test_login_new_user(get_ip_information_string_mock, db_session):
    """
    Test that if a user is not in the database and logs in, the user is added to the
    database and the session will contain the user's information.
    """
    email = "testuser@gmail.com"
    provider = "Test Provider"
    id_from_idp = "Provider_ID_0001"

    is_logged_in = login_user_or_require_registration(
        email, provider, email=email, id_from_idp=id_from_idp
    )
    assert is_logged_in

    test_user = db_session.query(User).filter(User.username == email.lower()).first()

    assert test_user.identity_provider.name == provider
    assert test_user.id_from_idp == id_from_idp
    assert test_user.email == email
    assert flask.session["username"] == email
    assert flask.session["provider"] == provider
    assert flask.session["user_id"] == str(test_user.id)
    assert flask.g.user == test_user

    assert get_ip_information_string_mock.called


def test_login_new_user_not_allowed(db_session, monkeypatch):
    """
    Test that when ALLOW_NEW_USER_ON_LOGIN config is False,
    and a user that is not in the database logs in, an
    Unauthorized error is returned.
    """
    monkeypatch.setitem(config, "ALLOW_NEW_USER_ON_LOGIN", False)
    email = "testuser@gmail.com"
    provider = "Test Provider"
    id_from_idp = "Provider_ID_0001"
    with pytest.raises(
        Unauthorized, match="New user is not yet authorized/activated in the system"
    ):
        login_user_or_require_registration(
            email, provider, email=email, id_from_idp=id_from_idp
        )


def test_last_auth_update_in_db(db_session):
    """
    Test that the _last_auth field in the DB is updated when the user logs in.
    """
    email = "testuser@gmail.com"
    provider = "Test Provider"
    id_from_idp = "Provider_ID_0001"

    test_user = User(username=email, is_admin=False)
    db_session.add(test_user)
    db_session.commit()

    logout("https://bogus.website")
    previous_login = test_user._last_auth

    time.sleep(5)

    is_logged_in = login_user_or_require_registration(
        email, provider, email=email, id_from_idp=id_from_idp
    )
    assert is_logged_in
    test_user_updated = db_session.query(User).filter(User.username == email).first()

    assert test_user_updated._last_auth > previous_login
