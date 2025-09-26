import os
from unittest.mock import MagicMock, patch

import flask
import pytest

from fence.blueprints.login import get_idp_route_name
from fence.blueprints.login.base import _login_and_register
from fence.config import config
from fence.errors import UserError
from tests.conftest import all_available_idps
from test_login_redirect import get_value_from_discovery_doc_patcher


@pytest.fixture
def enable_user_registration(request):
    """
    Temporarily enable `REGISTER_USERS_ON` in the config and, if requested,
    `OPENID_CONNECT.mock_idp.enable_idp_users_registration`.
    Revert those settings after running the test.
    """
    enable_registration = getattr(request, "param", {}).get("enable_registration", True)
    auto_register_users = getattr(request, "param", {}).get(
        "auto_register_users", False
    )

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
        response, user_is_logged_in = _login_and_register(email, provider)

        assert response.status_code == 200
        assert response.json == {"username": email}
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

        response, user_is_logged_in = _login_and_register(
            email, provider, token_result=token_result
        )

        # Ensure response is a JSON response
        assert response.status_code == 200
        assert response.json == {"username": email}
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
            _login_and_register("lisa", provider, token_result=token_result)


def test_login_redirect_after_login_with_registration(app, enable_user_registration):
    """
    Test that users are redirected to the registration page when IdP registration is disabled.
    """
    with app.app_context():
        response, user_is_logged_in = _login_and_register("lisaferf", "mock_idp")

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
        response, user_is_logged_in = _login_and_register("lisa", "mock_idp")

        assert response.status_code == 302
        assert response.location == redirect_url
        assert user_is_logged_in == True


@pytest.mark.parametrize("idp", all_available_idps())
def test_idp_login_stores_post_registration_redirect(
    app, client, idp, enable_user_registration, get_value_from_discovery_doc_patcher
):
    """
    Test that ALL IdPs store the `post_registration_redirect` in the current session during the
    login flow.
    """
    if idp == "fence":
        mocked_generate_authorize_redirect = MagicMock(
            return_value={"url": "authorization_url", "state": "state"}
        )
        mock = patch(
            f"authlib.integrations.flask_client.apps.FlaskOAuth2App.create_authorization_url",
            mocked_generate_authorize_redirect,
        ).start()

    try:
        url = f"/login/{get_idp_route_name(idp)}?redirect={app.config['BASE_URL']}"
        r = client.get(url)
        assert r.status_code == 302, r.text
        assert (
            flask.session.get("post_registration_redirect") == config["BASE_URL"] + url
        )

    finally:
        if idp == "fence":
            mock.stop()


@pytest.mark.parametrize("idp", all_available_idps())
@pytest.mark.parametrize(
    "enable_user_registration",
    [{"enable_registration": True}, {"enable_registration": False}],
    ids=["enable_registration", "disable_registration"],
    indirect=True,
)
def test_idp_callback_redirects_to_registration(
    app,
    client,
    idp,
    enable_user_registration,
    mocks_for_idp_oauth2_callbacks,
    db_session,
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


@pytest.mark.parametrize("idp", [all_available_idps()[0]])
def test_register_endpoint(
    idp, client, enable_user_registration, mocks_for_idp_oauth2_callbacks
):
    """
    Before starting the login flow, the registration endpoint should return 401.
    After starting the login flow, it should return an HTML page with a form.
    """
    # avoid error `A secret key is required to use CSRF` when the registration form
    # is created
    flask.current_app.config["WTF_CSRF_ENABLED"] = False

    try:
        r = client.get("/register")
        assert r.status_code == 401

        _, _, callback_endpoint, headers = mocks_for_idp_oauth2_callbacks
        r = client.get(
            f"/login/{get_idp_route_name(idp)}/{callback_endpoint}", headers=headers
        )
        assert r.status_code == 302

        r = client.get("/register")
        assert r.status_code == 200, r.text
        assert (
            "<!doctype html>" in r.text and "</form>" in r.text
        ), "Expected an HTML form"
    finally:
        flask.current_app.config["WTF_CSRF_ENABLED"] = True
