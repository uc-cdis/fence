import os
from unittest.mock import patch

import flask
import pytest

from fence.blueprints.login import get_idp_route_name
from fence.blueprints.login.base import _login
from fence.config import config
from fence.errors import UserError
from tests.conftest import LOGIN_IDPS


@pytest.fixture
def enable_user_registration(request):
    """
    Temporarily enable `REGISTER_USERS_ON` in the config and, if requested,
    `OPENID_CONNECT.mock_idp.enable_idp_users_registration`.
    Revert those settings after running the test.
    """
    enable_registration = (
        hasattr(request, "param") and request.param.get("enable_registration")
    ) or True
    auto_register_users = (
        hasattr(request, "param") and request.param.get("auto_register_users")
    ) or False
    if enable_registration:
        config["REGISTER_USERS_ON"] = True
    if auto_register_users:
        config["OPENID_CONNECT"]["mock_idp"] = {"enable_idp_users_registration": True}

    yield enable_registration, auto_register_users

    config["REGISTER_USERS_ON"] = False
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
@pytest.mark.parametrize(
    "enable_user_registration", [{"auto_register_users": True}], indirect=True
)
def test_login_with_auto_registration(
    mock_add_user_registration_info_to_database, app, enable_user_registration
):
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
        assert user_is_logged_in == True

        # Ensure user was added to the database
        mock_add_user_registration_info_to_database.assert_called()


@pytest.mark.parametrize(
    "enable_user_registration", [{"auto_register_users": True}], indirect=True
)
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


def test_login_redirect_after_login_with_registration(app, enable_user_registration):
    """
    Test that users are redirected to the registration page when IdP registration is disabled.
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


@pytest.mark.parametrize("idp", LOGIN_IDPS)
@pytest.mark.parametrize(
    "enable_user_registration",
    [{"enable_registration": True}, {"enable_registration": False}],
    ids=["enable_registration", "disable_registration"],
    indirect=True,
)
def test_idp_callback_redirects_to_registration(
    app, client, idp, enable_user_registration, mocks_for_idp_oauth2_callbacks
):
    """
    Test that ALL IdPs redirect users to the registration page when `REGISTER_USERS_ON` is enabled
    in the configuration, and do not when `REGISTER_USERS_ON` is disabled.
    """
    _, _, callback_endpoint, headers = mocks_for_idp_oauth2_callbacks

    r = client.get(
        f"/login/{get_idp_route_name(idp)}/{callback_endpoint}", headers=headers
    )
    registration_enabled, _ = enable_user_registration
    if registration_enabled:
        assert r.status_code == 302, r.text
        assert r.location == "http://localhost/user/user/register/"
    else:
        assert r.status_code == 200, r.text


@pytest.mark.parametrize("idp", [LOGIN_IDPS[0]])
def test_register_endpoint(
    idp, client, enable_user_registration, mocks_for_idp_oauth2_callbacks
):
    """
    Before starting the login flow, the registration endpoint should return 401.
    After starting the login flow, it should return an HTML page with a form.
    """
    # avoid error `A secret key is required to use CSRF` when the registration form
    # is created
    csrf_key_config_backup = flask.current_app.config["WTF_CSRF_SECRET_KEY"]
    flask.current_app.config["WTF_CSRF_SECRET_KEY"] = os.urandom(32)

    try:
        r = client.get("/register")
        assert r.status_code == 401, r.text

        _, _, callback_endpoint, headers = mocks_for_idp_oauth2_callbacks
        r = client.get(
            f"/login/{get_idp_route_name(idp)}/{callback_endpoint}", headers=headers
        )
        assert r.status_code == 302, r.text

        r = client.get("/register")
        assert r.status_code == 200, r.text
        assert "<!doctype html>" in r.text and "</form>" in r.text, "Expected an HTLM form"
    finally:
        flask.current_app.config["WTF_CSRF_SECRET_KEY"] = csrf_key_config_backup
