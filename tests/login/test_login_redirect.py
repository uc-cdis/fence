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

from tests.conftest import LOGIN_IDPS


def test_get_value_from_discovery_doc(app):
    """
    Test that both `discovery_url` and `discovery` can be used to configure
    the discovery doc in `OPENID_CONNECT`, and that default values are used
    when the requested key is not in the discovery doc.
    """
    # Scenario: config with `discovery` and no `discovery_url` (IDP generic2)
    # - get a key that is in the discovery data
    authorization_endpoint = app.generic2_client.get_value_from_discovery_doc(
        "authorization_endpoint", "default"
    )
    assert authorization_endpoint == "https://generic2/authorization_endpoint"

    # - get a key that is not in the discovery data
    other_endpoint = app.generic2_client.get_value_from_discovery_doc(
        "other_endpoint", "default"
    )
    assert other_endpoint == "default"

    # Scenario: config with `discovery_url` (IDP generic1)
    class MockResponse:
        def __init__(self):
            self.status_code = 200

        def json(self):
            return {"authorization_endpoint": "https://generic1/authorization_endpoint"}

    app.generic1_client.discovery_doc = MockResponse()

    # - get a key that is in the discovery data
    authorization_endpoint = app.generic1_client.get_value_from_discovery_doc(
        "authorization_endpoint", "default"
    )
    assert authorization_endpoint == "https://generic1/authorization_endpoint"

    # - get a key that is not in the discovery data
    authorization_endpoint = app.generic1_client.get_value_from_discovery_doc(
        "other_endpoint", "default"
    )
    assert authorization_endpoint == "default"


@pytest.fixture(scope="function")
def get_value_from_discovery_doc_patcher():
    mocks = []
    to_patch = [e for e in LOGIN_IDPS if e not in ["fence", "shib"]]
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
            return_value=("authorization_url", "state")
        )
        mock = patch(
            f"flask.current_app.fence_client.generate_authorize_redirect",
            mocked_generate_authorize_redirect,
        ).start()

    redirect = app.config["BASE_URL"]
    response = client.get("/login/{}?redirect={}".format(idp, redirect))
    assert response.status_code == 302

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
    response = client.get("/login/{}?redirect={}".format(idp, oauth_client.url))
    assert response.status_code == 302


@pytest.mark.parametrize("idp", LOGIN_IDPS)
def test_invalid_redirect_fails(client, idp):
    """
    Check that giving a bogus redirect to the login endpoint returns an error.
    """
    response = client.get("/login/{}?redirect=https://evil-site.net".format(idp))
    assert response.status_code == 400
