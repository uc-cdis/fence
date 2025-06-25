import pytest
from unittest.mock import MagicMock, patch

from fence import Oauth2ClientBase
from fence.resources.openid.cilogon_oauth2 import CilogonOauth2Client


@pytest.fixture
def mock_settings():
    """Fixture to create mock settings."""
    return {
        "client_id": "mock_client_id",
        "client_secret": "mock_client_secret",
        "redirect_url": "https://mock-redirect.com",
        "scope": "openid email profile",
    }


@pytest.fixture
def mock_logger():
    """Fixture to create a mock logger."""
    return MagicMock()


@pytest.fixture
def cilogon_client(mock_settings, mock_logger):
    """Fixture to create a CilogonOauth2Client instance."""
    return CilogonOauth2Client(mock_settings, mock_logger)


@pytest.fixture
def oauth2_client():
    """Fixture to create an instance of Oauth2ClientBase with a mocked session."""
    mock_settings = {
        "client_id": "mock_client_id",
        "client_secret": "mock_client_secret",
        "redirect_url": "https://mock-redirect.com",
        "scope": "openid email profile",
        "discovery_url": "https://mock-discovery.com",
    }
    mock_logger = MagicMock()

    client = Oauth2ClientBase(mock_settings, mock_logger, idp="MockIDP")
    client.session = MagicMock()

    return client


@patch("fence.resources.openid.cilogon_oauth2.Oauth2ClientBase.__init__")
def test_cilogon_client_init(mock_super_init, mock_settings, mock_logger):
    """
    Test that the CilogonOauth2Client initializes correctly and calls the parent class.
    """
    client = CilogonOauth2Client(mock_settings, mock_logger)

    mock_super_init.assert_called_once_with(
        mock_settings,
        mock_logger,
        scope="openid email profile",
        idp="CILogon",
        HTTP_PROXY=None,
    )

    assert (
        client.DISCOVERY_URL == "https://cilogon.org/.well-known/openid-configuration"
    )


@patch(
    "fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_value_from_discovery_doc"
)
def test_get_auth_url(mock_get_value_from_discovery_doc, app, oauth2_client):
    """
    Test that get_auth_url correctly constructs the authorization URL.
    """
    mock_get_value_from_discovery_doc.return_value = "https://cilogon.org/authorize"
    oauth2_client.session.create_authorization_url.return_value = (
        "https://mock-auth-url.com",
        None,
    )

    auth_url = oauth2_client.get_auth_url()

    assert auth_url == "https://mock-auth-url.com"
    mock_get_value_from_discovery_doc.assert_called_once_with(
        "authorization_endpoint", ""
    )
    oauth2_client.session.create_authorization_url.assert_called_once_with(
        "https://cilogon.org/authorize", prompt="login"
    )


@patch(
    "fence.resources.openid.cilogon_oauth2.Oauth2ClientBase.get_value_from_discovery_doc"
)
@patch("fence.resources.openid.cilogon_oauth2.Oauth2ClientBase.get_jwt_claims_identity")
def test_get_auth_info_success(
    mock_get_jwt_claims_identity, mock_get_value_from_discovery_doc, cilogon_client
):
    """
    Test that get_auth_info correctly extracts user claims when authentication is successful.
    """
    mock_get_value_from_discovery_doc.side_effect = [
        "https://cilogon.org/oauth2/token",
        "https://cilogon.org/oauth2/certs",
    ]

    mock_get_jwt_claims_identity.return_value = (
        {"sub": "mock_user_id"},
        "mock_refresh_token",
        "mock_access_token",
    )

    auth_info = cilogon_client.get_auth_info("mock_code")

    assert auth_info == {"sub": "mock_user_id"}
    mock_get_value_from_discovery_doc.assert_any_call(
        "token_endpoint", "https://cilogon.org/oauth2/token"
    )
    mock_get_value_from_discovery_doc.assert_any_call(
        "jwks_uri", "https://cilogon.org/oauth2/certs"
    )
    mock_get_jwt_claims_identity.assert_called_once_with(
        "https://cilogon.org/oauth2/token",
        "https://cilogon.org/oauth2/certs",
        "mock_code",
    )


@patch("fence.resources.openid.cilogon_oauth2.Oauth2ClientBase.get_jwt_claims_identity")
def test_get_auth_info_missing_sub(mock_get_jwt_claims_identity, cilogon_client):
    """
    Test that get_auth_info returns an error when 'sub' claim is missing.
    """
    mock_get_jwt_claims_identity.return_value = (
        {},  # No 'sub' in claims
        "mock_refresh_token",
        "mock_access_token",
    )

    auth_info = cilogon_client.get_auth_info("mock_code")

    assert auth_info == {"error": "Can't get user's CILogon sub"}


@patch("fence.resources.openid.cilogon_oauth2.Oauth2ClientBase.get_jwt_claims_identity")
def test_get_auth_info_exception(mock_get_jwt_claims_identity, cilogon_client):
    """
    Test that get_auth_info handles exceptions and logs an error.
    """
    mock_get_jwt_claims_identity.side_effect = Exception("Test Exception")

    auth_info = cilogon_client.get_auth_info("mock_code")

    assert "error" in auth_info
    assert "Can't get your CILogon sub" in auth_info["error"]
    cilogon_client.logger.exception.assert_called_once_with("Can't get user info")
