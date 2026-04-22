from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import grants
from authlib.oidc.core.errors import (
    AccountSelectionRequiredError,
    ConsentRequiredError,
    LoginRequiredError,
)
from authlib.oauth2.rfc6749 import (
    InvalidRequestError,
    UnauthorizedClientError,
    InvalidGrantError,
)
import flask
from fence.utils import get_valid_expiration_from_request
from fence.config import config
from fence.models import AuthorizationCode, ClientAuthType, User
from cdislogging import get_logger

logger = get_logger(__name__)


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):

    TOKEN_ENDPOINT_AUTH_METHODS = [auth_type.value for auth_type in ClientAuthType]

    def __init__(self, *args, **kwargs):
        super(AuthorizationCodeGrant, self).__init__(*args, **kwargs)
        # Override authlib validate_request_prompt with our own, to fix login prompt behavior
        self.register_hook(
            "after_validate_consent_request", self.validate_request_prompt
        )

    @staticmethod
    def create_authorization_code(client, grant_user, request):
        """
        Create an ``AuthorizationCode`` model for the current OAuth request
        from the given client and user.

        Certain parameters in the ``AuthorizationCode`` are filled out using
        the arguments passed from the OAuth request (the redirect URI, scope,
        and nonce).
        """

        # requested lifetime (in seconds) for the refresh token
        refresh_token_expires_in = get_valid_expiration_from_request(
            expiry_param="refresh_token_expires_in",
            max_limit=config["REFRESH_TOKEN_EXPIRES_IN"],
            default=config["REFRESH_TOKEN_EXPIRES_IN"],
        )

        code = AuthorizationCode(
            code=generate_token(50),
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=grant_user.id,
            nonce=request.data.get("nonce"),
            refresh_token_expires_in=refresh_token_expires_in,
        )

        with flask.current_app.db.session as session:
            session.add(code)
            session.commit()

        return code.code

    def save_authorization_code(self, code, request):
        """Save authorization_code for later use. Must be implemented.

        Args:
            code: authorization code string
            request: HTTP request

        Returns:
           authorization code string
        """
        # requested lifetime (in seconds) for the refresh token
        refresh_token_expires_in = get_valid_expiration_from_request(
            expiry_param="refresh_token_expires_in",
            max_limit=config["REFRESH_TOKEN_EXPIRES_IN"],
            default=config["REFRESH_TOKEN_EXPIRES_IN"],
        )

        client = request.client
        code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.payload.scope,
            user_id=request.user.id,
            nonce=request.payload.data.get("nonce"),
            refresh_token_expires_in=refresh_token_expires_in,
        )

        with flask.current_app.db.session as session:
            session.add(code)
            session.commit()
        return code.code

    def generate_token(self, *args, **kwargs):
        return self.server.generate_token(*args, **kwargs)

    def create_token_response(self):
        """Generate Tokens

        Raises:
            InvalidRequestError: if no user present in authorization code

        Returns:
            HTTP status code, token, HTTP response header
        """
        client = self.request.client
        authorization_code = self.request.authorization_code

        user = self.authenticate_user(authorization_code)
        if not user:
            raise InvalidRequestError('There is no "user" for this code.')

        scope = authorization_code.scope
        nonce = authorization_code.nonce
        refresh_token_expires_in = authorization_code.refresh_token_expires_in

        token = self.generate_token(
            client,
            self.GRANT_TYPE,
            user=user,
            scope=scope,
            include_refresh_token=bool(client.client_secret),
            nonce=nonce,
            refresh_token_expires_in=refresh_token_expires_in,
        )

        self.request.user = user
        self.server.save_token(token, self.request)
        self.execute_hook("process_token", token=token)
        self.delete_authorization_code(authorization_code)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    @staticmethod
    def query_authorization_code(code, client):
        """
        Search for an ``AuthorizationCode`` matching the given code string and
        client.

        Args:
            code (str): the code string for the ``AuthorizationCode``
            client (Client): the client the code was issued to

        Return:
            AuthorizationCode
        """
        with flask.current_app.db.session as session:
            authorization_code = (
                session.query(AuthorizationCode)
                .filter_by(code=code, client_id=client.client_id)
                .first()
            )
        if not authorization_code or authorization_code.is_expired():
            return None
        return authorization_code

    @staticmethod
    def delete_authorization_code(authorization_code):
        """
        Delete a saved authorization code.

        Args:
            authorization_code (AuthorizationCode):
                the ``AuthorizationCode`` to delete

        Return:
            None
        """
        with flask.current_app.db.session as session:
            session.delete(authorization_code)
            session.commit()

    @staticmethod
    def authenticate_user(authorization_code):
        with flask.current_app.db.session as session:
            return session.query(User).filter_by(id=authorization_code.user_id).first()

    def exists_nonce(self, nonce, request):
        with flask.current_app.db.session as session:
            code = session.query(AuthorizationCode).filter_by(nonce=nonce).first()
            if code:
                return True
            return False

    def validate_request_prompt(self, end_user, redirect_uri):
        """
        Override method in authlib to fix behavior with login prompt.
        """
        prompt = self.request.payload.data.get("prompt")
        if not prompt:
            if not end_user:
                self.prompt = "login"
            return self

        if prompt == "none" and not end_user:
            raise LoginRequiredError()

        prompts = prompt.split()
        if "none" in prompts and len(prompts) > 1:
            # If this parameter contains none with any other value,
            # an error is returned
            raise InvalidRequestError('Invalid "prompt" parameter.')
        if "login" in prompts:
            prompt = "login"
        if "consent" in prompts:
            if not end_user:
                raise ConsentRequiredError()
            prompt = "consent"
        elif "select_account" in prompts:
            if not end_user:
                raise AccountSelectionRequiredError()
            prompt = "select_account"

        if prompt:
            self.prompt = prompt

        return self

    def validate_token_request(self):
        """
        Validate token request by checking allowed grant type,
        making sure authorization code is found, and redirect URI is valid

        Raises:
            UnauthorizedClientError: if grant type is incorrect
            InvalidRequestError: if authorization code is absent
            InvalidGrantError: if authorization code is invalid
            InvalidGrantError: if redirect_uri is invalid
        """
        # authenticate the client if client authentication is included
        logger.debug("Authenticating token client..")
        client = self.authenticate_token_endpoint_client()

        logger.debug("Validate token request of %r", client)
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f'The client is not authorized to use "grant_type={self.GRANT_TYPE}"'
            )

        code = self.request.payload.data.get("code")
        if code is None:
            raise InvalidRequestError('Missing "code" in request.')

        # ensure that the authorization code was issued to the authenticated
        # confidential client, or if the client is public, ensure that the
        # code was issued to "client_id" in the request
        authorization_code = self.query_authorization_code(code, client)
        if not authorization_code:
            raise InvalidGrantError("Invalid 'code' in request.")

        # validate redirect_uri parameter
        logger.debug("Validate token redirect_uri of %r", client)
        redirect_uri = self.request.payload.redirect_uri
        original_redirect_uri = authorization_code.get_redirect_uri()
        if original_redirect_uri and redirect_uri != original_redirect_uri:
            raise InvalidGrantError("Invalid 'redirect_uri' in request.")

        # save for create_token_response
        self.request.client = client
        self.request.authorization_code = authorization_code
        self.execute_hook("after_validate_token_request")
