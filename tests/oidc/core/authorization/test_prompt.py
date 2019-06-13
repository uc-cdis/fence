"""
OIDC specification of authentication request parameter ``prompt``:

    OPTIONAL. Space delimited, case sensitive list of ASCII string values that
    specifies whether the Authorization Server prompts the End-User for
    reauthentication and consent. The defined values are:
        none
            The Authorization Server MUST NOT display any authentication or
            consent user interface pages. An error is returned if an End-User
            is not already authenticated or the Client does not have
            pre-configured consent for the requested Claims or does not fulfill
            other conditions for processing the request. The error code will
            typically be ``login_required``, ``interaction_required``, or
            another code defined in Section 3.1.2.6. This can be used as a
            method to check for existing authentication and/or consent.
        login
            The Authorization Server SHOULD prompt the End-User for
            reauthentication. If it cannot reauthenticate the End-User, it MUST
            return an error, typically ``login_required``.
        consent
            The Authorization Server SHOULD prompt the End-User for consent
            before returning information to the Client. If it cannot obtain
            consent, it MUST return an error, typically ``consent_required``.
        select_account
            The Authorization Server SHOULD prompt the End-User to select a
            user account. This enables an End-User who has multiple accounts at
            the Authorization Server to select amongst the multiple accounts
            that they might have current sessions for. If it cannot obtain an
            account selection choice made by the End-User, it MUST return an
            error, typically account_selection_required.
"""

import flask
import pytest

from fence.config import config

from unittest.mock import patch

from urllib.parse import urlparse, parse_qs


# Reasons for skipping tests.
CANT_CHOOSE_ACCOUNT = (
    "We don't support choosing an account at this point since users can only"
    " have one account."
)
NO_PRECONFIGURED_CONSENT = (
    "We don't have infrastructure to allow pre-configured consent on specific"
    " claims right now. Also, our current implementation tries to AuthN user"
    " by redirecting to login without checking prompt param right now."
)
PROMPT_CONSENT = (
    "Current implementation will continue to try and authenticate user before"
    " checking for prompt. We do not support the desired (but non-required)"
    " behavior for the consent value for prompt."
)


def check_for_error(response_location, error):
    """
    For the case that an error is expected in the OAuth redirect from the
    authorization endpoint. Check for an error named ``error`` in the location
    from a response.
    """
    query_params = parse_qs(urlparse(response_location).query)
    assert "error" in query_params
    assert query_params["error"][0] == error


@pytest.fixture(scope="function")
def patch_mock_auth_off(app, monkeypatch):
    """Don't mock auth so there isn't a logged in user."""
    monkeypatch.setitem(config, "MOCK_AUTH", False)
    monkeypatch.setitem(config, "DEFAULT_LOGIN_URL", "/login/google")


@pytest.fixture(scope="function")
def check_render_template(oauth_test_client):

    old_flask_render_template = flask.render_template

    def render_template(*args, **kwargs):
        return old_flask_render_template(*args, **kwargs)

    def check(data, called):
        """Make sure consent screen/page does or does not appear."""
        mock_render_template = patch(
            "flask.render_template", side_effect=render_template
        )
        with mock_render_template as render_mock:
            oauth_test_client.authorize(method="GET", data=data, do_asserts=False)
            assert render_mock.called == called

    return check


def test_no_prompt_provided(oauth_test_client, check_render_template):
    """``prompt`` is optional; test that omitting it is fine."""
    check_render_template(data={}, called=True)


@pytest.mark.skip(reason=NO_PRECONFIGURED_CONSENT)
def test_prompt_none_logged_in_client_cfg(oauth_test_client, check_render_template):
    """
    Test ``prompt=none`` when user is authN'd and client
    has pre-configured consent for the requested Claims. This is the
    only case where a successful response occurs.
    """
    data = {"confirm": "yes", "prompt": "none"}
    check_render_template(data=data, called=False)


@pytest.mark.skip(reason=NO_PRECONFIGURED_CONSENT)
@pytest.mark.parametrize("preconfigured_consent", ["yes", "no"])  # example
def test_prompt_none_not_logged_in_client_cfg(
    preconfigured_consent,
    app,
    oauth_test_client,
    patch_mock_auth_off,
    check_render_template,
):
    """
    Test ``prompt=none`` when user is not authN'd and client DOES have
    pre-configured consent for the requested Claims.
    """
    data = {"prompt": "none"}
    check_render_template(data=data, called=False)
    # TODO give client pre-cfg consent
    auth_response = oauth_test_client.authorize(data=data)
    check_for_error(auth_response.location, "access_denied")


@pytest.mark.skip(reason=NO_PRECONFIGURED_CONSENT)
def test_prompt_none_not_logged_in_client_not_cfg(
    app, oauth_test_client, patch_mock_auth_off, check_render_template
):
    """
    Test ``prompt=none`` when user is not authN'd and client DOES NOT have
    pre-configured consent for the requested Claims.
    """
    data = {"prompt": "none"}

    # TODO make client not have pre-cfg consent

    check_render_template(data=data, called=False)

    # Now use fake user consent confirmation
    data.update({"confirm": "yes"})
    auth_response = oauth_test_client.authorize(data=data)
    check_for_error(auth_response.location, "access_denied")


@pytest.mark.skip(reason=NO_PRECONFIGURED_CONSENT)
def test_prompt_none_logged_in_client_not_cfg(oauth_test_client, check_render_template):
    """
    Test ``prompt=none`` when user is authN'd and client does not
    have pre-configured consent for the requested Claims.
    """
    data = {"prompt": "none"}
    # TODO make client not have pre-cfg consent
    check_render_template(data={"prompt": "none"}, called=False)
    # Now use fake user consent confirmation
    data.update({"confirm": "yes"})
    auth_response = oauth_test_client.authorize(data=data)
    check_for_error(auth_response.location, "access_denied")


def test_prompt_login(oauth_test_client):
    """
    Test ``prompt=login`` when user re-AuthN's.
    """
    data = {"prompt": "login"}
    # Test with POST.
    oauth_test_client.authorize(data=data, do_asserts=False).response
    # Test with GET.
    # (For a GET without ``confirm == 'yes'``, the test client ordinarily would
    # expect the response to be 200 for rendering confirmation. However, this
    # should redirect to authorization endpoint, so we expect 302.)
    oauth_test_client.authorize(method="GET", data=data, do_asserts=False)
    response = oauth_test_client.authorize_response.response
    assert response.status_code == 302


@pytest.mark.skip(reason=PROMPT_CONSENT)
def test_prompt_consent_no_login(app, oauth_test_client, patch_mock_auth_off):
    """
    Test ``prompt=consent`` when user is not logged in, should raise error.
    """
    data = {"prompt": "consent"}
    auth_response = oauth_test_client.authorize(data=data)
    check_for_error(auth_response.location, "access_denied")


@pytest.mark.skip(reason=PROMPT_CONSENT)
def test_prompt_consent(app, oauth_test_client, check_render_template):
    """
    Test ``prompt=consent`` when user approves. Should display consent
    screen and then have correct response.
    """
    data = {"prompt": "consent"}
    check_render_template(data=data, called=True)
    # Now use fake user consent confirmation
    data.update({"confirm": "yes"})
    oauth_test_client.authorize(data=data)


@pytest.mark.skip(reason="changed login prompt to redirect to authorize")
def test_prompt_login_no_consent(app, oauth_test_client, check_render_template):
    """
    Test ``prompt=login`` when user does not consent. Should still show
    consent screen but then return with error.
    """
    data = {"prompt": "login"}
    check_render_template(data=data, called=True)
    data.update({"confirm": "no"})
    auth_response = oauth_test_client.authorize(
        method="GET", data=data, do_asserts=False
    )
    assert auth_response.response.status_code == 302
    assert auth_response.response.location
    check_for_error(auth_response.location, "access_denied")


@pytest.mark.skip(reason=CANT_CHOOSE_ACCOUNT)
def test_prompt_select_account(oauth_test_client):
    """
    Test ``prompt=select_account`` when user chooses an account.
    """
    # TODO check that account selection screen shows up

    oauth_test_client.authorize(data={"prompt": "select_account"})


@pytest.mark.skip(reason=CANT_CHOOSE_ACCOUNT)
def test_prompt_select_account_no_choice(oauth_test_client):
    """
    Test ``prompt=select_account`` when choice cannot be obtained.
    """

    # TODO check that account selection screen shows up
    # TODO force result to be no choice from selection options

    data = {"prompt": "select_account"}
    auth_response = oauth_test_client.authorize(data=data)
    check_for_error(auth_response.location, "account_selection_required")
