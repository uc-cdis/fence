import flask
import pytest
from fence.blueprints.login import DefaultOAuth2Callback
from fence.config import config
from unittest.mock import MagicMock, patch
from fence.errors import UserError
from fence.blueprints.login.base import _login


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


@pytest.fixture
def enable_user_registration(request):
    auto_register_users = hasattr(request, "param") and request.param.get("auto_register_users")
    config["REGISTER_USERS_ON"] = True
    if auto_register_users:
        config["OPENID_CONNECT"]["mock_idp"] = {"enable_idp_users_registration": True}

    yield

    config["REGISTER_USERS_ON"] = False
    if auto_register_users:
        config["OPENID_CONNECT"]["mock_idp"] = {"enable_idp_users_registration": False}


def test_login_existing_user_without_registration(app, db_session):
    """
    Test logging in an existing user without registration.
    """
    with app.app_context():
        email = "test@example.com"
        provider = "Test Provider"
        response, user_is_logged_in = _login(email, provider)

        assert response.status_code == 200
        assert response.json == {"username": email, "registered": True}
        assert user_is_logged_in == True


@patch("fence.blueprints.login.base.add_user_registration_info_to_database")
@pytest.mark.parametrize("enable_user_registration", [{"auto_register_users": True}], indirect=True)
def test_login_with_auto_registration(mock_add_user_registration_info_to_database, app, enable_user_registration):
    """
    Test logging in a user when registration is enabled.
    """
    with app.app_context():
        email = "lisa@example.com"
        provider = "mock_idp"
        token_result = {
            "firstname": "Lisa",
            "lastname": "Simpson",
            "org": "Springfield Elementary",
            "email": email,
        }

        response, user_is_logged_in = _login(email, provider, token_result=token_result)

        # Ensure response is a JSON response
        assert response.status_code == 200
        assert response.json == {"username": email, "registered": True}
        assert user_is_logged_in == False

        # Ensure user was added to the database
        mock_add_user_registration_info_to_database.assert_called()


@pytest.mark.parametrize("enable_user_registration", [{"auto_register_users": True}], indirect=True)
def test_login_with_auto_registration_and_missing_email(app, enable_user_registration):
    """
    Test that a missing email raises a UserError.
    """
    with app.app_context():
        provider = "mock_idp"
        token_result = {
            "firstname": "Lisa",
            "lastname": "Simpson",
            "org": "Springfield Elementary",
        }

        with pytest.raises(UserError, match="OAuth2 id token is missing email claim"):
            _login("lisa", provider, token_result=token_result)


def test_login_redirect_after_login_with_registration(
    app, enable_user_registration
):
    """
    Test that users are redirected to the registration page when IDP registration is disabled.
    """
    with app.app_context():
        response, user_is_logged_in = _login("lisaferf", "mock_idp")

        assert response.status_code == 302
        assert response.location == "http://localhost/user/user/register/"
        assert user_is_logged_in == False


def test_login_redirect_after_login_without_registration(app):
    """
    Test that users are redirected to their stored session redirect after authentication.
    """
    with app.app_context():
        redirect_url = "http://localhost/test-redirect"
        flask.session["redirect"] = redirect_url
        response, user_is_logged_in = _login("lisa", "mock_idp")

        assert response.status_code == 302
        assert response.location == redirect_url
        assert user_is_logged_in == True
