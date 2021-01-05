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


@pytest.mark.parametrize("idp", ["google", "shib", "microsoft", "orcid", "ras"])
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_valid_redirect_base(mock_discovery, app, client, idp):
    """
    Check that a valid redirect is allowed, using the base URL for this application as
    the destination for the redirect.
    """
    mock_discovery.return_value = "https://ras/token_endpoint"

    redirect = app.config["BASE_URL"]
    response = client.get("/login/{}?redirect={}".format(idp, redirect))
    assert response.status_code == 302


@pytest.mark.parametrize("idp", ["google", "shib", "microsoft", "orcid", "ras"])
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_valid_redirect_oauth(mock_discovery, client, oauth_client, idp):
    """
    Check that a valid redirect is allowed. Here we use the URL from the test OAuth
    client.
    """
    mock_discovery.return_value = "https://ras/token_endpoint"

    response = client.get("/login/{}?redirect={}".format(idp, oauth_client.url))
    assert response.status_code == 302


@pytest.mark.parametrize("idp", ["google", "shib", "microsoft", "orcid", "ras"])
def test_invalid_redirect_fails(client, idp):
    """
    Check that giving a bogus redirect to the login endpoint returns an error.
    """
    response = client.get("/login/{}?redirect=https://evil-site.net".format(idp))
    assert response.status_code == 400
