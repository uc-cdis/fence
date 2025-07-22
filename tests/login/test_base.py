import flask
import pytest
from fence.blueprints.login import DefaultOAuth2Callback
from fence.config import config
from unittest.mock import MagicMock, patch
from fence.errors import UserError
from fence.auth import login_user
from fence.blueprints.login.base import _login
from fence.models import User, IdentityProvider


@patch("fence.blueprints.login.base.prepare_login_log")
def test_post_login_set_mfa(app, monkeypatch, mock_authn_user_flask_context):
    """
    Verifies the arborist is called with the mfa_policy if a given token contains the claims found in the
    configured multifactor_auth_claim_info
    """
    monkeypatch.setitem(
        config,
        "OPENID_CONNECT",
        {
            "mock_idp": {
                "multifactor_auth_claim_info": {"claim": "acr", "values": ["mfa"]}
            }
        },
    )
    callback = DefaultOAuth2Callback(
        "mock_idp", MagicMock(), username_field="username", app=app
    )

    app.arborist = MagicMock()
    token_result = {"username": "lisasimpson", "mfa": True}
    callback.post_login(token_result=token_result)
    app.arborist.grant_user_policy.assert_called_with(
        username=token_result["username"], policy_id="mfa_policy"
    )

    token_result = {"username": "homersimpson", "mfa": False}
    callback.post_login(token_result=token_result)
    app.arborist.revoke_user_policy.assert_called_with(
        username=token_result["username"], policy_id="mfa_policy"
    )


@patch("fence.blueprints.login.base.prepare_login_log")
def test_post_login_no_mfa_enabled(app, monkeypatch, mock_authn_user_flask_context):
    """
    Verifies arborist is not called when there is no multifactor_auth_claim_info defined for the given IDP.
    """
    app.arborist = MagicMock()
    monkeypatch.setitem(
        config,
        "OPENID_CONNECT",
        {"mock_idp": {}},
    )
    with app.app_context():
        callback = DefaultOAuth2Callback(
            "mock_idp", MagicMock(), username_field="username"
        )
        token_result = {"username": "lisasimpson"}
        callback.post_login(token_result=token_result)
        app.arborist.revoke_user_policy.assert_not_called()
        yield


@pytest.fixture
def mock_user():
    """Fixture to mock a logged-in user with additional_info."""
    user = MagicMock()
    user.additional_info = {}
    return user


@patch("fence.auth.login_user")
def test_login_existing_user(mock_login_user, db_session, app):
    """
    Test logging in an existing user without registration.
    """
    with app.app_context():
        email = "test@example.com"
        provider = "Test Provider"

        response = _login(email, provider)

        mock_login_user.assert_called_once_with(
            email, provider, email=None, id_from_idp=None
        )

        assert response.status_code == 200
        assert response.json == {"username": email, "registered": True}
        yield


@patch("fence.auth.login_user")
@patch("fence.blueprints.login.base.current_app.scoped_session")
def test_login_with_registration(mock_scoped_session, mock_login_user, db_session, app):
    """
    Test logging in a user when registration is enabled.
    """
    with app.app_context():
        config.REGISTER_USERS_ON = True
        config["OPENID_CONNECT"]["mock_idp"] = {"enable_idp_users_registration": True}
        config.REGISTERED_USERS_GROUP = "test_group"

        email = "lisa@example.com"
        provider = "mock_idp"
        token_result = {
            "firstname": "Lisa",
            "lastname": "Simpson",
            "org": "Springfield Elementary",
            "email": email,
        }

        response = _login(email, provider, token_result=token_result)

        # Ensure login was called
        mock_login_user.assert_called_once_with(
            email, provider, email=email, id_from_idp=None
        )

        # Ensure user was added to the database
        mock_scoped_session.add.assert_called()
        mock_scoped_session.commit.assert_called()

        # Ensure response is a JSON response
        assert response.status_code == 200
        assert response.json == {"username": email, "registered": True}
        yield


@patch("fence.auth.login_user")
def test_login_with_missing_email(mock_login_user, app, monkeypatch):
    """
    Test that a missing email raises a UserError.
    """
    with app.app_context():
        config["REGISTER_USERS_ON"] = True
        config["OPENID_CONNECT"]["mock_idp"] = {"enable_idp_users_registration": True}

        provider = "mock_idp"
        token_result = {
            "firstname": "Lisa",
            "lastname": "Simpson",
            "org": "Springfield Elementary",
        }
        yield

        with pytest.raises(UserError, match="OAuth2 id token is missing email claim"):
            _login("lisa", provider, token_result=token_result)


@patch("fence.auth.login_user")
def test_login_redirect_to_registration_page(
    mock_login_user, app, monkeypatch, db_session
):
    """
    Test that users are redirected to the registration page when IDP registration is disabled.
    """
    with app.app_context():
        config["REGISTER_USERS_ON"] = True
        config["OPENID_CONNECT"]["mock_idp"] = {"enable_idp_users_registration": False}

        db_session.query(User).delete()  # Remove all users from DB for this test
        db_session.commit()

        response = _login("lisaferf", "mock_idp")

        assert response.status_code == 302
        assert response.location == "http://localhost/user/register"
        yield


@patch("fence.auth.login_user")
def test_login_redirect_after_authentication(mock_login_user, app):
    """
    Test that users are redirected to their stored session redirect after authentication.
    """
    with app.app_context():
        flask.session["redirect"] = "http://localhost/"

        response = _login("lisa", "mock_idp")

        assert response.status_code == 302
        assert response.location == "http://localhost/"
        yield
