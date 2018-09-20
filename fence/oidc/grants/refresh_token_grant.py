import bcrypt

from authlib.specs.rfc6749.errors import (
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    UnauthorizedClientError,
)
from authlib.specs.rfc6749.grants import RefreshTokenGrant as AuthlibRefreshTokenGrant
from authlib.specs.rfc6749.util import scope_to_list
import flask

from fence.jwt.blacklist import is_token_blacklisted
from fence.jwt.errors import JWTError
from fence.jwt.validate import validate_jwt
from fence.models import ClientAuthType, User


class RefreshTokenGrant(AuthlibRefreshTokenGrant):
    """
    Implement the refresh token grant which the OIDC provider will use.

    This class both implements some methods required by authlib, and overrides
    others to change the default behavior from authlib; see method docstrings
    for details.

    NOTE: ``self._authenticated_token`` is the refresh token claims as a
    dictionary; ``self.params['refresh_token']`` is the actual string.
    """

    TOKEN_ENDPOINT_AUTH_METHODS = [auth_type.value for auth_type in ClientAuthType]

    def authenticate_refresh_token(self, refresh_token):
        """
        Validate a refresh token.

        Required to implement this method for authlib.

        Args:
            refresh_token (str): refresh token as from a request

        Return:
            dict: the claims from the validated token
        """
        try:
            if is_token_blacklisted(refresh_token):
                return
        except JWTError:
            return
        return validate_jwt(refresh_token, purpose="refresh")

    def create_access_token(self, token, client, authenticated_token):
        """
        Authlib requires the implementation of this method to save the token.
        However, fence does not save the access tokens to a database, so just
        return the original token again.
        """
        return token

    @staticmethod
    def authenticate_user(claims):
        """
        Return user from the claims (decoded from JWT). Required for authlib.
        """
        user_id = claims.get("sub")
        if not user_id:
            return None
        with flask.current_app.db.session as session:
            return session.query(User).filter_by(id=user_id).first()

    def validate_token_request(self):
        """
        Override over authlib to allow public clients to use refresh tokens.
        """
        client = self.authenticate_token_endpoint_client()
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError("invalid grant type")
        self.request.client = client
        self.authenticate_token_endpoint_client()
        token = self._validate_request_token()
        self._validate_token_scope(token)
        self.request.credential = token

    def validate_access_token_request(self):
        """
        Override the parent method from authlib to not fail immediately for
        public clients.
        """
        client = self.authenticate_token_endpoint_client()
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(uri=self.uri)
        self._authenticated_client = client

        refresh_token = self.params.get("refresh_token")
        if refresh_token is None:
            raise InvalidRequestError(
                'Missing "refresh_token" in request.', uri=self.uri
            )

        refresh_claims = self.authenticate_refresh_token(refresh_token)
        if not refresh_claims:
            raise InvalidRequestError(
                'Invalid "refresh_token" in request.', uri=self.uri
            )

        scope = self.params.get("scope")
        if scope:
            original_scope = refresh_claims["scope"]
            if not original_scope:
                raise InvalidScopeError(uri=self.uri)
            original_scope = set(scope_to_list(original_scope))
            if not original_scope.issuperset(set(scope_to_list(scope))):
                raise InvalidScopeError(uri=self.uri)

        self._authenticated_token = refresh_claims

    def create_token_response(self):
        """
        OVERRIDES method from authlib.

        Docs from authlib:

            If valid and authorized, the authorization server issues an access
            token as described in Section 5.1. If the request failed
            verification or is invalid, the authorization server returns an
            error response as described in Section 5.2.
        """
        credential = self.request.credential
        user = self.authenticate_user(credential)
        if not user:
            raise InvalidRequestError('There is no "user" for this token.')

        scope = self.request.scope
        if not scope:
            scope = credential["aud"]

        client = self.request.client
        expires_in = credential["exp"]
        token = self.generate_token(
            client, self.GRANT_TYPE, user=user, expires_in=expires_in, scope=scope
        )
        # TODO
        flask.current_app.logger.info("")

        self.request.user = user
        self.server.save_token(token, self.request)
        token = self.process_token(token, self.request)
        return 200, token, self.TOKEN_RESPONSE_HEADER
