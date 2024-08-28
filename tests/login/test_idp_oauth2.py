import pytest
import datetime
from jose import jwt
from jose.exceptions import JWTClaimsError
from unittest.mock import ANY
from flask import Flask, g
from cdislogging import get_logger
from unittest.mock import MagicMock, Mock, patch
from fence.resources.openid.idp_oauth2 import Oauth2ClientBase, AuthError
from fence.blueprints.login.base import DefaultOAuth2Callback

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

@pytest.fixture
def settings():
    return {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "redirect_url": "http://localhost/callback",
        "discovery_url": "http://localhost/.well-known/openid-configuration",
        "groups": {"read_group_information": True, "group_prefix": "/"},
        "user_id_field": "sub",
    }

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

@pytest.fixture
def oauth2_client(settings):
    # Mock settings
    mock_settings = settings

    # Mock logger
    mock_logger = MagicMock()

    # Initialize the Oauth2ClientBase instance with mock settings and logger
    client = Oauth2ClientBase(settings=mock_settings, logger=mock_logger, idp="test_idp")

    return client

# To test the store_refresh_token method of the Oauth2ClientBase class
def test_store_refresh_token(app,settings):
    """
    Test the `store_refresh_token` method of the `Oauth2ClientBase` class to ensure that
    refresh tokens are correctly stored in the database using the `UpstreamRefreshToken` model.

    This test covers:
      1. Verifying that a new instance of `UpstreamRefreshToken` is created with the correct
         user, refresh token, and expiration time.
      2. Ensuring that the database session's `add` and `commit` methods are called to save
         the refresh token into the database.
      3. Patching the `UpstreamRefreshToken` class to prevent actual database interactions.

    Args:
        app (Flask app): The application instance containing the mock Arborist service and database session.
        settings (Settings): Configuration settings for the `Oauth2ClientBase` instance.

    Test Flow:
        1. Initializes an `Oauth2ClientBase` instance with mocked settings and logger.
        2. Patches the `UpstreamRefreshToken` model to avoid actual database access.
        3. Calls the `store_refresh_token` method with mock user, refresh token, and expiration time.
        4. Verifies that:
           - The `UpstreamRefreshToken` is instantiated correctly with the user, refresh token, and expiration.
           - The database session's `add` and `commit` methods are called to save the token.
           - The `add` method receives the newly created `UpstreamRefreshToken` object.

    Example Mock Data:
        - `refresh_token`: "mock_refresh_token"
        - `expires`: 1700000000 (timestamp for token expiration)

    Assertions:
        - Checks that the `UpstreamRefreshToken` model was instantiated with the correct parameters.
        - Ensures that the `add` method is called on the database session to add the `UpstreamRefreshToken` instance.
        - Confirms that the `commit` method is called on the database session to persist the changes.

    Raises:
        AssertionError: If the expected database interactions or method calls are not performed.
    """
    # Create an instance of Oauth2ClientBase
    mock_logger = MagicMock()
    app.arborist = MagicMock()
    mock_user = MagicMock()
    mock_settings = settings
    client = Oauth2ClientBase(settings=mock_settings, logger=mock_logger, idp="test_idp")

    # Patch the UpstreamRefreshToken to prevent actual database interactions
    with patch('fence.resources.openid.idp_oauth2.UpstreamRefreshToken', autospec=True) as MockUpstreamRefreshToken:
        # Call the method to test
        refresh_token = "mock_refresh_token"
        expires = 1700000000
        client.store_refresh_token(mock_user, refresh_token, expires, db_session=app.arborist)

        # Check if UpstreamRefreshToken was instantiated correctly
        MockUpstreamRefreshToken.assert_called_once_with(
            user=mock_user,
            refresh_token=refresh_token,
            expires=expires,
        )

        # Check if the mock session's `add` and `commit` methods were called
        app.arborist.object_session.assert_called_once()
        current_db_session = app.arborist.object_session.return_value
        current_db_session.add.assert_called_once()
        app.arborist.commit.assert_called_once()

        # Verify that the `add` method was called with the instance of UpstreamRefreshToken
        current_db_session.add.assert_called_once_with(MockUpstreamRefreshToken.return_value)

        # Ensure that the `store_refresh_token` method is called with the expected arguments
        MockUpstreamRefreshToken.assert_called_once_with(
            user=mock_user,
            refresh_token=refresh_token,
            expires=expires
        )

# To test if a user is granted access using the get_auth_info method in the Oauth2ClientBase
@patch('fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_jwt_keys')
@patch('fence.resources.openid.idp_oauth2.jwt.decode')
@patch('authlib.integrations.requests_client.OAuth2Session.fetch_token')
@patch('fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_value_from_discovery_doc')
def test_get_auth_info_granted_access(mock_get_value_from_discovery_doc, mock_fetch_token, mock_jwt_decode, mock_get_jwt_keys, oauth2_client):
    """
    Test that the `get_auth_info` method correctly retrieves, processes, and decodes
    an OAuth2 authentication token, including access, refresh, and ID tokens, while also
    handling JWT decoding and discovery document lookups.

    This test covers the following:
      1. Mocks the token and JWKS URIs retrieved from the OAuth2 discovery document.
      2. Mocks the access, ID, and refresh token response from the `fetch_token` method.
      3. Mocks the retrieval of JWT keys and simulates the JWT decoding process.
      4. Verifies that the resulting authentication information (`auth_info`) contains
         the expected fields, such as `sub`, `refresh_token`, `iat`, `exp`, and `groups`.

    Args:
        mock_get_value_from_discovery_doc (Mock): Mocked method that retrieves the token endpoint and JWKS URI from the discovery document.
        mock_fetch_token (Mock): Mocked method that simulates fetching the access, refresh, and ID tokens from the token endpoint.
        mock_jwt_decode (Mock): Mocked method that simulates decoding a JWT token.
        mock_get_jwt_keys (Mock): Mocked method that returns a set of JWT keys used for validating the token.
        oauth2_client (Oauth2ClientBase): The instance of `Oauth2ClientBase` being tested, which handles OAuth2 operations.

    Test Flow:
        1. Mocks the `get_value_from_discovery_doc` method to return token and JWKS URIs.
        2. Mocks the `fetch_token` method to return an access token, ID token, and refresh token.
        3. Mocks the JWT keys returned by the authorization server's JWKS URI.
        4. Mocks the JWT decode process, simulating the decoded payload of the ID token.
        5. Calls `get_auth_info` with a mock authorization code and checks the returned auth info.
        6. Verifies that the expected claims (`sub`, `iat`, `exp`, and `groups`) and the `refresh_token`
           are included in the decoded authentication information.

    Assertions:
        - The `auth_info` dictionary contains the `sub` claim, which matches the mock user ID.
        - The `auth_info` includes the `refresh_token` from the `fetch_token` response.
        - The `iat` and `exp` claims are correctly decoded from the JWT.
        - The `groups` claim is populated with the correct group names from the decoded JWT.

    Example Mock Data:
        - Token Endpoint: "http://localhost/token"
        - JWKS URI: "http://localhost/jwks"
        - JWT Keys: A mock RSA key with "kid": "1e9gdk7".
        - JWT Payload: Contains claims like `sub`, `iat`, `exp`, and `groups`.

    Raises:
        AssertionError: If the expected claims or tokens are not present in the returned authentication information.
    """
    # Directly mock the return values for token_endpoint and jwks_uri
    mock_get_value_from_discovery_doc.side_effect = lambda key, default=None: \
        "http://localhost/token" if key == "token_endpoint" else "http://localhost/jwks"

    # Setup mock response for fetch_token
    mock_fetch_token.return_value = {
        "access_token": "mock_access_token",
        "id_token": "mock_id_token",
        "refresh_token": "mock_refresh_token"
    }

    # Setup mock JWT keys response
    mock_get_jwt_keys.return_value = [
        {
            "kty": "RSA",
            "kid": "1e9gdk7",
            "use": "sig",
            "n": "example-key",
            "e": "AQAB"
        }
    ]

    # Setup mock decoded JWT token
    mock_jwt_decode.return_value = {
        "sub": "mock_user_id",
        "email_verified": True,
        "iat": 1609459200,
        "exp": 1609462800,
        "groups": ["group1", "group2"]
    }


    # Log mock setups
    print(f"Mock token endpoint: {mock_get_value_from_discovery_doc('token_endpoint', '')}")
    print(f"Mock jwks_uri: {mock_get_value_from_discovery_doc('jwks_uri', '')}")
    print(f"Mock fetch_token response: {mock_fetch_token.return_value}")
    print(f"Mock JWT decode response: {mock_jwt_decode.return_value}")


    # Call the method
    code = "mock_code"
    auth_info = oauth2_client.get_auth_info(code)
    print(f"Mock auth_info: {auth_info}")

    # Debug: Check if decode was called
    print(f"JWT decode call count: {mock_jwt_decode.call_count}")

    # Assertions
    assert "sub" in auth_info
    assert auth_info["sub"] == "mock_user_id"
    assert "refresh_token" in auth_info
    assert auth_info["refresh_token"] == "mock_refresh_token"
    assert "iat" in auth_info
    assert auth_info["iat"] == 1609459200
    assert "exp" in auth_info
    assert auth_info["exp"] == 1609462800
    assert "groups" in auth_info
    assert auth_info["groups"] == ["group1", "group2"]


@pytest.fixture
def mock_db_session():
    """Mock the database session."""
    db_session = MagicMock()
    return db_session

@pytest.fixture
def expired_mock_user():
    """Mock a user object with upstream refresh tokens."""
    user = MagicMock()
    user.upstream_refresh_tokens = [
        MagicMock(refresh_token="expired_token", expires=0),  # Expired token
    ]
    return user

def test_get_access_token_expired(expired_mock_user, mock_db_session, settings):
    """
    Test that attempting to retrieve an access token for a user with an expired refresh token
    results in an `AuthError`, the user's token is deleted, and the session is committed.

    This test simulates a scenario where a user's token has expired and ensures that:
      1. The `get_access_token` method raises an `AuthError` when trying to use an expired token.
      2. The user's token is removed from the database.
      3. The changes are committed to the database.

    Args:
        expired_mock_user (Mock): Mock object representing a user with an expired refresh token.
        mock_db_session (Mock): Mocked database session object to track interactions with the database.
        settings (dict): Settings used to initialize the `Oauth2ClientBase` object, including OAuth2 configurations.

    Test Flow:
        1. Initializes the `Oauth2ClientBase` with mocked settings and logger.
        2. Simulates the scenario where `get_access_token` is called for a user with an expired token.
        3. Verifies that an `AuthError` is raised with the expected error message.
        4. Ensures that the expired token is deleted from the database, and the session is committed.

    Assertions:
        - An `AuthError` is raised with the message: "User doesn't have a valid, non-expired refresh token".
        - The `delete` method on the `mock_db_session` is called, indicating the token was removed.
        - The `commit` method on the `mock_db_session` is called, confirming the database transaction was completed.

    Raises:
        AuthError: When the user does not have a valid, non-expired refresh token.
    """

    # Initialize the Oauth2 client object
    client = Oauth2ClientBase(settings=settings, logger=MagicMock(), idp="test_idp")


    #Simulate the token expiration and user not having access
    with pytest.raises(AuthError) as excinfo:
        print("get_access_token about to be called")
        client.get_access_token(expired_mock_user, token_endpoint="https://token.endpoint", db_session=mock_db_session)

    print(f"Raised exception message: {excinfo.value}")

    assert "User doesn't have a valid, non-expired refresh token" in str(excinfo.value)

    mock_db_session.delete.assert_called()
    mock_db_session.commit.assert_called()


@patch('fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_auth_info')
def test_post_login_with_group_prefix(mock_get_auth_info, app):
    """
    Test the `post_login` method of the `DefaultOAuth2Callback` class, ensuring that user groups
    fetched from an identity provider (IdP) are processed correctly and prefixed before being added
    to the user in the Arborist service.

    This test mocks the OAuth2 flow and verifies that groups returned from the IdP are:
      1. Filtered to remove the given prefix (`covid/` in this case).
      2. Added to the Arborist service using the `add_user_to_group` method.

    It checks that the correct groups, without the prefix, are added to Arborist and that
    the method is called the appropriate number of times.

    Args:
        mock_get_auth_info (MagicMock): Mocked return value of the `get_auth_info` method, simulating
            the IdP response with user information and groups.
        app (Flask): The Flask app instance, which contains a mocked Arborist client for user-group management.

    Mocked Objects:
        - `mock_get_auth_info`: Returns mock user info and groups from the IdP.
        - `app.arborist`: A mocked Arborist service, which handles user group management.
        - `callback.app.arborist.add_user_to_group`: Mocked method to simulate adding a user to a group in Arborist.

    Test Flow:
        1. Sets up a mock return value for `get_auth_info` to simulate fetching groups from the IdP.
        2. Mocks the Arborist's `list_groups` method to return a predefined set of groups.
        3. Mocks the `add_user_to_group` method in the Arborist client to track which groups are added.
        4. Calls `post_login` on the `DefaultOAuth2Callback` class to process the user's groups.
        5. Verifies that the correct groups, stripped of their prefix, are added to Arborist.

    Assertions:
        - The `add_user_to_group` method is called with the correct group names (without the prefix) and user details.
        - The method is called three times, once for each group.

    Raises:
        AssertionError: If the number of calls to `add_user_to_group` or the group names do not match the expected values.
    """
    # Set up mock responses for user info and groups from the IdP
    mock_get_auth_info.return_value = {
        "username": "test_user",
        "groups": [
            "group1",
            "group2",
            "covid/group3",
            "group4",
            "group5"
        ],
        "exp": datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
    }

    app.arborist = MagicMock()
    mock_user = Mock()
    mock_user.username = "test_user"
    app.arborist.list_groups.return_value = {
        "groups": [{"name": "group1"}, {"name": "group2"},{"name": "group3"}, {"name": "reviewers"}]  # Arborist groups
    }


    mock_logger = MagicMock()

    callback = DefaultOAuth2Callback(
        "generic3", MagicMock(), username_field="test_user", app=app
    )
    # Create a mock for add_user_to_group
    mock_add_user_to_group = Mock()

    # Inject the mock into the callback instance
    callback.app.arborist.add_user_to_group = mock_add_user_to_group

    g.user = mock_user

    # Simulate calling post_login, which processes groups
    post_login_result = callback.post_login(
        user=mock_user,
        groups_from_idp=mock_get_auth_info.return_value["groups"],
        group_prefix="covid/",
        expires_at=mock_get_auth_info.return_value["exp"],
        username=mock_user.username
    )
    assert isinstance(callback.app.arborist.add_user_to_group, Mock)
    print(post_login_result)
    print(mock_add_user_to_group.mock_calls)

    # Assertions to check if groups were processed with the correct prefix
    mock_add_user_to_group.assert_any_call(username='test_user', group_name='group1', expires_at=ANY)
    mock_add_user_to_group.assert_any_call(username='test_user', group_name='group2', expires_at=ANY)
    mock_add_user_to_group.assert_any_call(username='test_user', group_name='group3', expires_at=ANY)

    # Ensure the mock was called thrice (once for each group)
    assert mock_add_user_to_group.call_count == 3



@patch('fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_jwt_keys')
@patch('authlib.integrations.requests_client.OAuth2Session.fetch_token')
@patch('fence.resources.openid.idp_oauth2.jwt.decode')  # Mock jwt.decode
def test_jwt_audience_verification_fails(mock_jwt_decode, mock_fetch_token, mock_get_jwt_keys):
    """
    Test the JWT audience verification failure scenario.

    This test mocks various components used in the OIDC flow to simulate the
    process of obtaining a token, fetching JWKS (JSON Web Key Set), and verifying
    the JWT token's claims. Specifically, it focuses on the audience verification
    step and tests that an invalid audience raises the expected `JWTClaimsError`.

    Mocks:
        - Oauth2Session.fetch_token: Simulates successful retrieval of tokens (id_token, access_token).
        - jwt.decode: Simulates decoding and verifying the JWT. In this case, raises `JWTClaimsError` to simulate audience verification failure.
        - Oauth2ClientBase.get_jwt_keys: Mocks fetching JWT keys used for decoding.

    Test Steps:
        1. Mocks the fetch_token to return a mock ID token.
        2. Mocks the JWKS response that provides public keys for JWT verification.
        3. Mocks jwt.decode to raise `JWTClaimsError` to simulate audience verification failure.
        4. Calls `get_jwt_claims_identity` and expects it to raise `JWTClaimsError`.
        5. Verifies that `fetch_token`, `requests.get`, and `jwt.decode` are called with the expected parameters.

    Raises:
        JWTClaimsError: When the audience in the JWT token is invalid.
    """
    # Mock fetch_token to simulate a successful token fetch
    mock_fetch_token.return_value = {
        "id_token": "mock-id-token",
        "access_token": "mock_access_token",
        "refresh_token": "mock-refresh-token"
    }

    # Mock JWKS response
    mock_jwks_response = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key-id",
                "use": "sig",
                "n": "mock-n-value",  # Simulate RSA public key values
                "e": "mock-e-value"
            }
        ]
    }

    mock_get_jwt_keys.return_value = MagicMock()
    mock_get_jwt_keys.return_value = mock_jwks_response

    # Mock jwt.decode to raise JWTClaimsError for audience verification failure
    mock_jwt_decode.side_effect = JWTClaimsError("Invalid audience")

    # Setup the mock instance of Oauth2ClientBase
    client = Oauth2ClientBase(
        settings={
            "client_id": "mock-client-id",
            "client_secret": "mock-client-secret",
            "redirect_url": "mock-redirect-url",
            "discovery_url": "http://localhost/discovery",
            "audience": "expected-audience",
            "verify_aud": True
        },
        logger=MagicMock(),
        idp="mock-idp"
    )

    # Invoke the method and expect JWTClaimsError to be raised
    with pytest.raises(JWTClaimsError, match="Invalid audience"):
        client.get_jwt_claims_identity(token_endpoint="https://token.endpoint", jwks_endpoint="https://jwks.uri", code="auth_code")

    # Verify fetch_token was called correctly
    mock_fetch_token.assert_called_once_with(
        url="https://token.endpoint",
        code="auth_code",
        proxies=None
    )

    #Verify jwt.decode was called with the mock id_token and the mocked JWKS keys
    mock_jwt_decode.assert_called_with(
        "mock-id-token",  # The mock token
        mock_jwks_response, # The mocked keys
        options={"verify_aud": True, "verify_at_hash": False},
        algorithms=["RS256"],
        audience="expected-audience"
    )