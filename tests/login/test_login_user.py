import flask
from flask_sqlalchemy_session import current_session
from fence.auth import login_user, logout
from fence.models import User, IdentityProvider
import time
from datetime import datetime


def test_login_user_already_in_db(db_session):
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

    login_user(email, provider, email=email, id_from_idp=id_from_idp)

    assert test_user.identity_provider.name == provider
    assert test_user.id_from_idp == id_from_idp
    assert test_user.email == email
    assert flask.session["username"] == email
    assert flask.session["provider"] == provider
    assert flask.session["user_id"] == user_id
    assert flask.g.user == test_user


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

    login_user(email, provider, email=email, id_from_idp=id_from_idp)

    assert test_user.identity_provider.name == provider
    assert test_user.id_from_idp == id_from_idp
    assert test_user.email == email
    assert flask.session["username"] == email
    assert flask.session["provider"] == provider
    assert flask.session["user_id"] == user_id
    assert flask.g.user == test_user


def test_login_new_user(db_session):
    """
    Test that if a user is not in the database and logs in, the user is added to the
    database and the session will contain the user's information.
    """
    email = "testuser@gmail.com"
    provider = "Test Provider"
    id_from_idp = "Provider_ID_0001"

    login_user(email, provider, email=email, id_from_idp=id_from_idp)

    test_user = db_session.query(User).filter(User.username == email.lower()).first()

    assert test_user.identity_provider.name == provider
    assert test_user.id_from_idp == id_from_idp
    assert test_user.email == email
    assert flask.session["username"] == email
    assert flask.session["provider"] == provider
    assert flask.session["user_id"] == str(test_user.id)
    assert flask.g.user == test_user


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

    login_user(email, provider, email=email, id_from_idp=id_from_idp)
    test_user_updated = db_session.query(User).filter(User.username == email).first()

    assert test_user_updated._last_auth > previous_login
