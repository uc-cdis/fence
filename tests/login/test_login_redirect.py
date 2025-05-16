"""
Fence's login endpoints must redirect only to valid URLs:

    - the same application (``BASE_URL``)
    - registered in the configuration
    - registered for an OAuth client

Mocking `get_value_from_discovery_doc` for RAS because
https://sts.nih.gov is not stable and causes test failures.
"""

import pytest
from unittest.mock import MagicMock, patch

from fence.blueprints.login import get_idp_route_name
from fence.config import config
from tests.conftest import LOGIN_IDPS


def test_get_value_from_discovery_doc(app):
    """
    Test that both `discovery_url` and `discovery` can be used to configure
    the discovery doc in `OPENID_CONNECT`, and that default values are used
    when the requested key is not in the discovery doc.
    """
    # Scenario: config with `discovery` and no `discovery_url` (IDP generic_with_discovery_block)
    # - get a key that is in the discovery data
    authorization_endpoint = (
        app.generic_with_discovery_block_client.get_value_from_discovery_doc(
            "authorization_endpoint", "default"
        )
    )
    assert (
        authorization_endpoint
        == "https://generic_with_discovery_block/authorization_endpoint"
    )

    # - get a key that is not in the discovery data
    other_endpoint = (
        app.generic_with_discovery_block_client.get_value_from_discovery_doc(
            "other_endpoint", "default"
        )
    )
    assert other_endpoint == "default"

    # Scenario: config with `discovery_url` (IDP generic_with_discovery_url)
    class MockResponse:
        def __init__(self):
            self.status_code = 200

        def json(self):
            return {
                "authorization_endpoint": "https://generic_with_discovery_url/authorization_endpoint"
            }

    app.generic_with_discovery_url_client.discovery_doc = MockResponse()

    # - get a key that is in the discovery data
    authorization_endpoint = (
        app.generic_with_discovery_url_client.get_value_from_discovery_doc(
            "authorization_endpoint", "default"
        )
    )
    assert (
        authorization_endpoint
        == "https://generic_with_discovery_url/authorization_endpoint"
    )

    # - get a key that is not in the discovery data
    authorization_endpoint = (
        app.generic_with_discovery_url_client.get_value_from_discovery_doc(
            "other_endpoint", "default"
        )
    )
    assert authorization_endpoint == "default"


@pytest.fixture(scope="function")
def get_value_from_discovery_doc_patcher():
    mocks = []
    to_patch = [e for e in LOGIN_IDPS if e not in ["fence", "shibboleth"]]
    for idp in to_patch:
        mock = MagicMock()
        mock.return_value = ""
        if idp.startswith("generic"):
            class_file = "idp_oauth2.Oauth2ClientBase"
        elif idp == "ras":
            class_file = "ras_oauth2.RASOauth2Client"
        else:
            class_file = f"{idp}_oauth2.{idp.title()}Oauth2Client"
        mock_discovery = patch(
            f"fence.resources.openid.{class_file}.get_value_from_discovery_doc",
            mock,
        )
        mock_discovery.start()
        mocks.append(mock_discovery)

    yield

    for mock in mocks:
        mock.stop()


@pytest.mark.parametrize("idp", LOGIN_IDPS)
def test_valid_redirect_base(app, client, idp, get_value_from_discovery_doc_patcher):
    """
    Check that a valid redirect is allowed, using the base URL for this application as
    the destination for the redirect.
    """
    if idp == "fence":
        mocked_generate_authorize_redirect = MagicMock(
            return_value={"url": "authorization_url", "state": "state"}
        )
        mock = patch(
            f"authlib.integrations.flask_client.apps.FlaskOAuth2App.create_authorization_url",
            mocked_generate_authorize_redirect,
        ).start()

    redirect = app.config["BASE_URL"]
    login_url = "/login/{}?redirect={}".format(get_idp_route_name(idp), redirect)

    # test `authorization_url_param_map` functionality
    authorization_url_param_map = config["OPENID_CONNECT"][idp].get(
        "authorization_url_param_map", {}
    )
    for in_param in authorization_url_param_map:
        if in_param == "key_not_in_login_url":
            # do not add this parameter to the login URL
            continue
        login_url += f"&{in_param}=param_value"

    response = client.get(login_url)
    assert response.status_code == 302

    redirect_location = response.headers["Location"]
    for in_param, out_param in authorization_url_param_map.items():
        if in_param == "key_not_in_login_url":
            # check that if a parameter configured in `authorization_url_param_map` is not in the
            # login URL, it is not added to the redirect URL
            assert f"&{out_param}=param_value" not in redirect_location
        else:
            # other parameters should be mapped to the configured `out_param` and added to the
            # redirect URL
            assert f"&{out_param}=param_value" in redirect_location

    if idp == "fence":
        mock.stop()


@pytest.mark.parametrize("idp", LOGIN_IDPS)
def test_valid_redirect_oauth(
    client,
    oauth_client,
    idp,
    get_value_from_discovery_doc_patcher,
):
    """
    Check that a valid redirect is allowed. Here we use the URL from the test OAuth
    client.
    """
    response = client.get(
        "/login/{}?redirect={}".format(get_idp_route_name(idp), oauth_client.url)
    )
    assert response.status_code == 302


@pytest.mark.parametrize("idp", LOGIN_IDPS)
def test_invalid_redirect_fails(client, idp):
    """
    Check that giving a bogus redirect to the login endpoint returns an error.
    """
    response = client.get(
        "/login/{}?redirect=https://evil-site.net".format(get_idp_route_name(idp))
    )
    assert response.status_code == 400
