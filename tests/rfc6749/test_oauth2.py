"""
Test the endpoints in the ``/oauth2`` blueprint.
"""

import pytest

from fence.jwt.token import SCOPE_DESCRIPTION
from fence.config import config


def test_all_scopes_have_description():
    for scope in config["CLIENT_ALLOWED_SCOPES"]:
        assert scope in SCOPE_DESCRIPTION


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_oauth2_authorize(oauth_test_client, method):
    """Test ``/oauth2/authorize``."""
    data = {"confirm": "yes"}
    oauth_test_client.authorize(method=method, data=data)


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_oauth2_authorize_incorrect_scope(oauth_test_client, method):
    """Test ``/oauth2/authorize``."""
    data = {"confirm": "yes", "scope": "openid wrong_code"}
    auth_response = oauth_test_client.authorize(
        method=method, data=data, do_asserts=False
    )
    assert auth_response.response.status_code == 401


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_oauth2_authorize_get_public_client(oauth_test_client_public, method):
    """Test ``/oauth2/authorize`` with a public client."""
    data = {"confirm": "yes"}
    oauth_test_client_public.authorize(method=method, data=data)


def test_oauth2_token_post(oauth_test_client):
    """Test ``POST /oauth2/token``."""
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    oauth_test_client.token()


def test_oauth2_token_post_public_client(oauth_test_client_public):
    """Test ``POST /oauth2/token`` for public client."""
    data = {"confirm": "yes"}
    oauth_test_client_public.authorize(data=data)
    oauth_test_client_public.token()


@pytest.mark.parametrize("refresh_data", [{}, {"scope": "openid"}])
def test_oauth2_token_refresh(oauth_test_client, refresh_data):
    """Test the refresh endpoint."""
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    oauth_test_client.token()
    oauth_test_client.refresh(data=refresh_data)


@pytest.mark.parametrize("refresh_data", [{}, {"scope": "openid"}])
def test_oauth2_token_refresh_public_client(oauth_test_client_public, refresh_data):
    """Test the refresh endpoint for public client."""
    data = {"confirm": "yes"}
    oauth_test_client_public.authorize(data=data)
    oauth_test_client_public.token()
    oauth_test_client_public.refresh(data=refresh_data)


def test_oauth2_token_post_revoke(oauth_test_client):
    """
    Test the following procedure:
    - ``POST /oauth2/authorize`` successfully to obtain code
    - ``POST /oauth2/token`` successfully to obtain token
    - ``POST /oauth2/revoke`` to revoke the refresh token
    - Refresh token should no longer be usable at this point.
    """
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    oauth_test_client.token()
    oauth_test_client.revoke()
    # Try to use refresh token.
    refresh_token = oauth_test_client.token_response.refresh_token
    oauth_test_client.refresh(refresh_token, do_asserts=False)
    response = oauth_test_client.refresh_response.response
    assert response.status_code == 400
