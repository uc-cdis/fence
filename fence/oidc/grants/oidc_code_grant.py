from authlib.common.security import generate_token
from authlib.oidc.core import grants
from authlib.oidc.core.errors import (
    AccountSelectionRequiredError,
    ConsentRequiredError,
    LoginRequiredError,
)
from authlib.oauth2.rfc6749 import InvalidRequestError
import flask
from fence.utils import get_valid_expiration_from_request
from fence.config import config
from fence.models import AuthorizationCode, ClientAuthType, User


class OpenIDCodeGrant(grants.OpenIDCodeGrant):

    TOKEN_ENDPOINT_AUTH_METHODS = [auth_type.value for auth_type in ClientAuthType]

    def __init__(self, *args, **kwargs):
        super(OpenIDCodeGrant, self).__init__(*args, **kwargs)
        # Override authlib validate_request_prompt with our own, to fix login prompt behavior
        self._hooks["after_validate_consent_request"].discard(
            grants.util.validate_request_prompt
        )
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
        refresh_token_expires_in = get_valid_expiration_from_request()
        if refresh_token_expires_in:
            refresh_token_expires_in = min(
                refresh_token_expires_in, config["REFRESH_TOKEN_EXPIRES_IN"]
            )
        else:
            refresh_token_expires_in = config["REFRESH_TOKEN_EXPIRES_IN"]

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

    def generate_token(self, *args, **kwargs):
        return self.server.generate_token(*args, **kwargs)

    def create_token_response(self):
        client = self.request.client
        authorization_code = self.request.credential

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
            include_refresh_token=client.has_client_secret(),
            nonce=nonce,
            refresh_token_expires_in=refresh_token_expires_in,
        )

        self.request.user = user
        self.server.save_token(token, self.request)
        self.execute_hook("process_token", token=token)
        self.delete_authorization_code(authorization_code)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    @staticmethod
    def parse_authorization_code(code, client):
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

    def validate_request_prompt(self, end_user):
        """
        Override method in authlib to fix behavior with login prompt.
        """
        prompt = self.request.data.get("prompt")
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
