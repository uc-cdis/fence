import jwt
import pytest
import datetime
from jose.exceptions import JWTClaimsError, JWTError
from unittest.mock import ANY
from flask import Flask, g
from cdislogging import get_logger
from unittest.mock import MagicMock, Mock, patch

from fence.resources.openid.idp_oauth2 import Oauth2ClientBase, AuthError
from fence.blueprints.login.base import DefaultOAuth2Callback
from fence.config import config


MOCK_SETTINGS_ACR = {
    "client_id": "client",
    "client_secret": "hunter2",
    "redirect_url": "localhost",
    "multifactor_auth_claim_info": {
        "claim": "acr",
        "values": ["mfa", "otp", "duo", "sms", "phonecall"],
    },
}
MOCK_SETTINGS_AMR = {
    "client_id": "client",
    "client_secret": "hunter2",
    "redirect_url": "localhost",
    "multifactor_auth_claim_info": {
        "claim": "amr",
        "values": ["mfa", "otp", "duo", "sms", "phonecall"],
    },
}
logger = get_logger(__name__, log_level="debug")


@pytest.fixture()
def oauth_client_acr():
    return Oauth2ClientBase(settings=MOCK_SETTINGS_ACR, idp="mock", logger=logger)


@pytest.fixture()
def oauth_client_amr():
    return Oauth2ClientBase(settings=MOCK_SETTINGS_AMR, idp="mock", logger=logger)


def test_has_mfa_claim_acr(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "mfa"})
    assert has_mfa


def test_has_mfa_claim_multiple_acr(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "mfa otp duo"})
    assert has_mfa


def test_does_not_has_mfa_claim(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "pwd"})
    assert not has_mfa

    has_mfa = oauth_client_acr.has_mfa_claim({"something": "mfa"})
    assert not has_mfa


def test_does_not_has_mfa_claim_multiple(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "pwd trustme"})
    assert not has_mfa


def test_has_mfa_claim_amr(oauth_client_amr):
    has_mfa = oauth_client_amr.has_mfa_claim({"amr": ["mfa"]})
    assert has_mfa


def test_has_mfa_claim_multiple_amr(oauth_client_amr):
    has_mfa = oauth_client_amr.has_mfa_claim({"amr": ["mfa", "otp", "duo"]})
    assert has_mfa


def test_does_not_has_mfa_claim_amr(oauth_client_amr):
    has_mfa = oauth_client_amr.has_mfa_claim({"amr": ["pwd"]})
    assert not has_mfa

    has_mfa = oauth_client_amr.has_mfa_claim({"something": ["mfa"]})
    assert not has_mfa


def test_does_not_has_mfa_claim_multiple_amr(oauth_client_amr):
    has_mfa = oauth_client_amr.has_mfa_claim({"amr": ["pwd, trustme"]})
    assert not has_mfa


# To test the store_refresh_token method of the Oauth2ClientBase class
def test_store_refresh_token(mock_user, mock_app):
    """
    Test the `store_refresh_token` method of the `Oauth2ClientBase` class to ensure that
    refresh tokens are correctly stored in the database using the `UpstreamRefreshToken` model.
    """
    mock_logger = MagicMock()
    mock_settings = {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "redirect_url": "http://localhost/callback",
        "discovery_url": "http://localhost/.well-known/openid-configuration",
        "groups": {"read_authz_groups_from_tokens": True, "group_prefix": "/"},
        "user_id_field": "sub",
    }

    # Ensure oauth_client is correctly instantiated
    oauth_client = Oauth2ClientBase(
        settings=mock_settings, logger=mock_logger, idp="test_idp"
    )

    refresh_token = "mock_refresh_token"
    expires = 1700000000

    # Patch the UpstreamRefreshToken to prevent actual database interactions
    with patch(
        "fence.resources.openid.idp_oauth2.UpstreamRefreshToken", autospec=True
    ) as MockUpstreamRefreshToken:

        # Call the method to test
        oauth_client.store_refresh_token(
            mock_user, refresh_token, expires, db_session=mock_app.arborist
        )

        # Check if UpstreamRefreshToken was instantiated correctly
        MockUpstreamRefreshToken.assert_called_once_with(
            user=mock_user,
            refresh_token=refresh_token,
            expires=expires,
        )

        # Check if the mock_app.arborist sent as a db_session's `add` and `commit` methods were called
        mock_app.arborist.add.assert_called_once_with(
            MockUpstreamRefreshToken.return_value
        )
        mock_app.arborist.commit.assert_called_once()


# To test if a user is granted access using the get_auth_info method in Oauth2ClientBase
@patch("fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_jwt_keys")
@patch("jwt.decode")
@patch("authlib.integrations.requests_client.OAuth2Session.fetch_token")
@patch(
    "fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_value_from_discovery_doc"
)
def test_get_auth_info_granted_access(
    mock_get_value_from_discovery_doc,
    mock_fetch_token,
    mock_jwt_decode,
    mock_get_jwt_keys,
    app,
):
    """
    Test that the `get_auth_info` method correctly retrieves, processes, and decodes
    an OAuth2 authentication token, including access, refresh, and ID tokens, while also
    handling JWT decoding and discovery document lookups.

    Raises:
        AssertionError: If the expected claims or tokens are not present in the returned authentication information.
    """

    mock_settings = {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "redirect_url": "http://localhost/callback",
        "discovery_url": "http://localhost/.well-known/openid-configuration",
        "is_authz_groups_sync_enabled": True,
        "authz_groups_sync": {"group_prefix": "/"},
        "user_id_field": "sub",
    }

    # Mock logger
    mock_logger = MagicMock()

    with app.app_context():
        yield
        oauth2_client = Oauth2ClientBase(
            settings=mock_settings, logger=mock_logger, idp="test_idp"
        )

        # Mock token endpoint and jwks_uri
        mock_get_value_from_discovery_doc.side_effect = lambda key, default=None: (
            "http://localhost/token"
            if key == "token_endpoint"
            else "http://localhost/jwks"
        )

        # Setup mock response for fetch_token
        mock_fetch_token.return_value = {
            "access_token": "mock_access_token",
            "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrX3VzZXJfaWQiLCJpYXQiOjE2MDk0NTkyMDAsImV4cCI6MTYwOTQ2MjgwMCwiZ3JvdXBzIjpbImdyb3VwMSIsImdyb3VwMiJdfQ.XYZ",
            "refresh_token": "mock_refresh_token",
        }

        # Setup mock JWT keys response
        mock_get_jwt_keys.return_value = [
            {
                "kty": "RSA",
                "kid": "1e9gdk7",
                "use": "sig",
                "n": "example-key",
                "e": "AQAB",
            }
        ]

        # Setup mock decoded JWT token
        mock_jwt_decode.return_value = {
            "sub": "mock_user_id",
            "email_verified": True,
            "iat": 1609459200,
            "exp": 1609462800,
            "groups": ["group1", "group2"],
        }

        # Log mock setups
        logger.debug(
            f"Mock token endpoint: {mock_get_value_from_discovery_doc('token_endpoint', '')}"
        )
        logger.debug(
            f"Mock jwks_uri: {mock_get_value_from_discovery_doc('jwks_uri', '')}"
        )
        logger.debug(f"Mock fetch_token response: {mock_fetch_token.return_value}")
        logger.debug(f"Mock JWT decode response: {mock_jwt_decode.return_value}")

        # Call the method
        code = "mock_code"
        auth_info = oauth2_client.get_auth_info(code)
        logger.debug(f"Mock auth_info: {auth_info}")

        # Debug: Check if decode was called
        logger.debug(f"JWT decode call count: {mock_jwt_decode.call_count}")
        logger.debug(f"Returned auth_info: {auth_info}")
        logger.debug(f"JWT decode call args: {mock_jwt_decode.call_args_list}")
        logger.debug(f"Fetch token response: {mock_fetch_token.return_value}")

        # Assertions
        assert "sub" in auth_info, f"Expected 'sub' in auth_info, got {auth_info}"
        assert auth_info["sub"] == "mock_user_id"
        assert "refresh_token" in auth_info
        assert auth_info["refresh_token"] == "mock_refresh_token"
        assert "iat" in auth_info
        assert auth_info["iat"] == 1609459200
        assert "exp" in auth_info
        assert auth_info["exp"] == 1609462800
        assert "groups" in auth_info
        assert auth_info["groups"] == ["group1", "group2"]


def test_get_access_token_expired(expired_mock_user, mock_db_session):
    """
    Test that attempting to retrieve an access token for a user with an expired refresh token
    results in an `AuthError`, the user's token is deleted, and the session is committed.


    Raises:
        AuthError: When the user does not have a valid, non-expired refresh token.
    """
    mock_settings = {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "redirect_url": "http://localhost/callback",
        "discovery_url": "http://localhost/.well-known/openid-configuration",
        "is_authz_groups_sync_enabled": True,
        "authz_groups_sync:": {"group_prefix": "/"},
        "user_id_field": "sub",
    }

    # Initialize the Oauth2 client object
    oauth2_client = Oauth2ClientBase(
        settings=mock_settings, logger=MagicMock(), idp="test_idp"
    )

    # Simulate the token expiration and user not having access
    with pytest.raises(AuthError) as excinfo:
        logger.debug("get_access_token about to be called")
        oauth2_client.get_access_token(
            expired_mock_user,
            token_endpoint="https://token.endpoint",
            db_session=mock_db_session,
        )

    logger.debug(f"Raised exception message: {excinfo.value}")

    assert "User doesn't have a valid, non-expired refresh token" in str(excinfo.value)

    mock_db_session.delete.assert_called()
    mock_db_session.commit.assert_called()


@patch("fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_auth_info")
def test_post_login_with_group_prefix(mock_get_auth_info, app):
    """
    Test the `post_login` method of the `DefaultOAuth2Callback` class, ensuring that user groups
    fetched from an identity provider (IdP) are processed correctly and prefixed before being added
    to the user in the Arborist service.
    """
    with app.app_context():
        yield
        with patch.dict(config, {"ENABLE_AUTHZ_GROUPS_FROM_OIDC": True}, clear=False):
            mock_user = MagicMock()
            mock_user.username = "test_user"
            mock_user.id = "user_id"
            g.user = mock_user

            # Set up mock responses for user info and groups from the IdP
            mock_get_auth_info.return_value = {
                "username": "test_user",
                "groups": ["group1", "group2", "covid/group3", "group4", "group5"],
                "exp": datetime.datetime.now(tz=datetime.timezone.utc).timestamp(),
                "group_prefix": "covid/",
            }

            # Mock the Arborist client and its methods
            mock_arborist = MagicMock()
            mock_arborist.list_groups.return_value = {
                "groups": [
                    {"name": "group1"},
                    {"name": "group2"},
                    {"name": "group3"},
                    {"name": "reviewers"},
                ]
            }
            mock_arborist.add_user_to_group = MagicMock()
            mock_arborist.remove_user_from_group = MagicMock()

            # Mock the Flask app
            app = MagicMock()
            app.arborist = mock_arborist

            # Create the callback object with the mock app
            callback = DefaultOAuth2Callback(
                idp_name="generic_additional_params", client=MagicMock(), app=app
            )

            # Mock user and call post_login
            mock_user = MagicMock()
            mock_user.username = "test_user"

            # Simulate calling post_login
            callback.post_login(
                user=g.user,
                token_result=mock_get_auth_info.return_value,
                groups_from_idp=mock_get_auth_info.return_value["groups"],
                group_prefix=mock_get_auth_info.return_value["group_prefix"],
                expires_at=mock_get_auth_info.return_value["exp"],
                username=mock_user.username,
            )

            # Assertions to check if groups were processed with the correct prefix
            mock_arborist.add_user_to_group.assert_any_call(
                username="test_user",
                group_name="group1",
                expires_at=datetime.datetime.fromtimestamp(
                    mock_get_auth_info.return_value["exp"], tz=datetime.timezone.utc
                ),
            )
            mock_arborist.add_user_to_group.assert_any_call(
                username="test_user",
                group_name="group2",
                expires_at=datetime.datetime.fromtimestamp(
                    mock_get_auth_info.return_value["exp"], tz=datetime.timezone.utc
                ),
            )
            mock_arborist.add_user_to_group.assert_any_call(
                username="test_user",
                group_name="group3",
                expires_at=datetime.datetime.fromtimestamp(
                    mock_get_auth_info.return_value["exp"], tz=datetime.timezone.utc
                ),
            )

            # Ensure the mock was called exactly three times (once for each group that was added)
            assert mock_arborist.add_user_to_group.call_count == 3


@patch("fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_jwt_keys")
@patch("authlib.integrations.requests_client.OAuth2Session.fetch_token")
@patch("fence.resources.openid.idp_oauth2.jwt.decode")  # Mock jwt.decode
def test_jwt_audience_verification_fails(
    mock_jwt_decode, mock_fetch_token, mock_get_jwt_keys
):
    """
    Test the JWT audience verification failure scenario.

    This test mocks various components used in the OIDC flow to simulate the
    process of obtaining a token, fetching JWKS (JSON Web Key Set), and verifying
    the JWT token's claims. Specifically, it focuses on the audience verification
    step and tests that an invalid audience raises the expected `JWTClaimsError`.


    Raises:
        JWTClaimsError: When the audience in the JWT token is invalid.
    """
    # Mock fetch_token to simulate a successful token fetch
    mock_fetch_token.return_value = {
        "id_token": "mock-id-token",
        "access_token": "mock_access_token",
        "refresh_token": "mock-refresh-token",
    }

    # Mock JWKS response
    mock_jwks_response = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key-id",
                "use": "sig",
                # Simulate RSA public key values
                "n": "mock-n-value",
                "e": "mock-e-value",
            }
        ]
    }

    mock_get_jwt_keys.return_value = MagicMock()
    mock_get_jwt_keys.return_value = mock_jwks_response

    # Mock jwt.decode to raise JWTClaimsError for audience verification failure
    mock_jwt_decode.side_effect = JWTError("Invalid audience")

    # Setup the mock instance of Oauth2ClientBase
    client = Oauth2ClientBase(
        settings={
            "client_id": "mock-client-id",
            "client_secret": "mock-client-secret",
            "redirect_url": "mock-redirect-url",
            "discovery_url": "http://localhost/discovery",
            "audience": "expected-audience",
            "verify_aud": True,
        },
        logger=MagicMock(),
        idp="mock-idp",
    )

    # Invoke the method and expect JWTClaimsError to be raised
    with pytest.raises(JWTError, match="Invalid audience"):
        client.get_jwt_claims_identity(
            token_endpoint="https://token.endpoint",
            jwks_endpoint="https://jwks.uri",
            code="auth_code",
        )

    # Verify fetch_token was called correctly
    mock_fetch_token.assert_called_once_with(
        url="https://token.endpoint", code="auth_code", proxies=None
    )

    # Verify jwt.decode was called with the mock id_token
    mock_jwt_decode.assert_called_with(
        "mock-id-token",  # The mock token
        key=mock_jwks_response,
        options={"verify_signature": False},
        algorithms=["RS256"],
    )
