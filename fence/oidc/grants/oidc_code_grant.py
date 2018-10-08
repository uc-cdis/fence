from authlib.common.security import generate_token
from authlib.specs.oidc import grants
from authlib.specs.oidc.errors import (
    AccountSelectionRequiredError,
    ConsentRequiredError,
    LoginRequiredError,
)
from authlib.specs.rfc6749 import InvalidRequestError
import flask

from fence.models import AuthorizationCode, ClientAuthType, User


class OpenIDCodeGrant(grants.OpenIDCodeGrant):

    TOKEN_ENDPOINT_AUTH_METHODS = [auth_type.value for auth_type in ClientAuthType]

    @staticmethod
    def create_authorization_code(client, grant_user, request):
        """
        Create an ``AuthorizationCode`` model for the current OAuth request
        from the given client and user.

        Certain parameters in the ``AuthorizationCode`` are filled out using
        the arguments passed from the OAuth request (the redirect URI, scope,
        and nonce).
        """
        code = AuthorizationCode(
            code=generate_token(50),
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=grant_user.id,
            nonce=request.data.get("nonce"),
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

        scope = authorization_code.get_scope()

        query_args = dict(self.request.query_params)
        nonce = self.request.body.get("nonce") or query_args.get("nonce")

        token = self.generate_token(
            client,
            self.GRANT_TYPE,
            user=user,
            scope=scope,
            include_refresh_token=client.has_client_secret(),
            nonce=nonce,
        )

        self.request.user = user
        self.server.save_token(token, self.request)
        token = self.process_token(token, self.request)
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

    def validate_nonce(self, required=False):
        """
        Override method in authlib to skip adding ``exists_nonce`` hook on server. I
        don't think this needs to exist according to OIDC spec but this stays consistent
        with authlib so here we are
        """
        if required:
            if not self.request.nonce:
                raise InvalidRequestError("Missing `nonce`")
            with flask.current_app.db.session as session:
                code = (
                    session.query(AuthorizationCode)
                    .filter_by(nonce=self.request.nonce)
                    .first()
                )
                if not code:
                    raise InvalidRequestError("Replay attack")
        return True

    def validate_prompt(self, end_user):
        """
        Override method in authlib to fix behavior with login prompt.
        """
        prompt = getattr(self.request, "prompt", None)
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
