"""
Fence's login endpoints must redirect only to valid URLs:

    - the same application (``BASE_URL``)
    - registered in the configuration
    - registered for an OAuth client
"""

import pytest


@pytest.mark.parametrize("idp", ["google", "shib"])
def test_valid_redirect_base(app, client, idp):
    """
    Check that a valid redirect is allowed, using the base URL for this application as
    the destination for the redirect.
    """
    redirect = app.config["BASE_URL"]
    response = client.get("/login/{}?redirect={}".format(idp, redirect))
    assert response.status_code == 302


@pytest.mark.parametrize("idp", ["google", "shib"])
def test_valid_redirect_oauth(client, oauth_client, idp):
    """
    Check that a valid redirect is allowed. Here we use the URL from the test OAuth
    client.
    """
    response = client.get("/login/google?redirect={}".format(oauth_client.url))
    assert response.status_code == 302


@pytest.mark.parametrize("idp", ["google", "shib"])
def test_invalid_redirect_fails(client, idp):
    """
    Check that giving a bogus redirect to the login endpoint returns an error.
    """
    response = client.get("/login/google?redirect=https://evil-site.net")
    assert response.status_code == 400
