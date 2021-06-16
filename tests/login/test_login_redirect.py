"""
Fence's login endpoints must redirect only to valid URLs:

    - the same application (``BASE_URL``)
    - registered in the configuration
    - registered for an OAuth client

Mocking `get_value_from_discovery_doc` for RAS because
https://sts.nih.gov is not stable and causes test failures.
"""

import mock
import pytest
from unittest.mock import MagicMock, patch

from fence.blueprints.login import IDP_URL_MAP


@pytest.mark.parametrize("idp", list(IDP_URL_MAP.values()))
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
@mock.patch(
    "fence.resources.openid.okta_oauth2.OktaOauth2Client.get_value_from_discovery_doc"
)
@mock.patch(
    "fence.resources.openid.cognito_oauth2.CognitoOauth2Client.get_value_from_discovery_doc"
)
def test_valid_redirect_base(
    mock_cognito_discovery, mock_okta_discovery, mock_ras_discovery, app, client, idp
):
    """
    Check that a valid redirect is allowed, using the base URL for this application as
    the destination for the redirect.
    """
    if idp == "fence":
        mocked_generate_authorize_redirect = MagicMock(
            return_value=("authorization_url", "state")
        )
        patch(
            f"flask.current_app.fence_client.generate_authorize_redirect",
            mocked_generate_authorize_redirect,
        ).start()
    elif idp == "ras":
        mock_ras_discovery.return_value = "https://ras/token_endpoint"
    elif idp == "cognito":
        mock_cognito_discovery.return_value = ""
    elif idp == "okta":
        mock_okta_discovery.return_value = ""

    redirect = app.config["BASE_URL"]
    response = client.get("/login/{}?redirect={}".format(idp, redirect))
    assert response.status_code == 302


@pytest.mark.parametrize("idp", list(IDP_URL_MAP.values()))
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
@mock.patch(
    "fence.resources.openid.okta_oauth2.OktaOauth2Client.get_value_from_discovery_doc"
)
@mock.patch(
    "fence.resources.openid.cognito_oauth2.CognitoOauth2Client.get_value_from_discovery_doc"
)
def test_valid_redirect_oauth(
    mock_cognito_discovery,
    mock_okta_discovery,
    mock_ras_discovery,
    client,
    oauth_client,
    idp,
):
    """
    Check that a valid redirect is allowed. Here we use the URL from the test OAuth
    client.
    """
    if idp == "ras":
        mock_ras_discovery.return_value = "https://ras/token_endpoint"
    elif idp == "cognito":
        mock_cognito_discovery.return_value = ""
    elif idp == "okta":
        mock_okta_discovery.return_value = ""

    response = client.get("/login/{}?redirect={}".format(idp, oauth_client.url))
    assert response.status_code == 302


@pytest.mark.parametrize("idp", list(IDP_URL_MAP.values()))
def test_invalid_redirect_fails(client, idp):
    """
    Check that giving a bogus redirect to the login endpoint returns an error.
    """
    response = client.get("/login/{}?redirect=https://evil-site.net".format(idp))
    assert response.status_code == 400
