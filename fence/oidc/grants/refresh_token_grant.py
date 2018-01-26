import bcrypt

from authlib.specs.rfc6749.errors import (
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    UnauthorizedClientError,
)
from authlib.specs.rfc6749.grants import (
    RefreshTokenGrant as AuthlibRefreshTokenGrant
)

from fence.jwt.blacklist import is_token_blacklisted
from fence.jwt.errors import JWTError
from fence.jwt.validate import validate_jwt


class RefreshTokenGrant(AuthlibRefreshTokenGrant):
    """
    Implement the refresh token grant which the OIDC provider will use.

    This class both implements some methods required by authlib, and overrides
    others to change the default behavior from authlib; see method docstrings
    for details.
    """

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
        return validate_jwt(refresh_token, purpose='refresh')

    def create_access_token(self, token, client, authenticated_token):
        """
        Authlib requires the implementation of this method to save the token.
        However, fence does not save the access tokens to a database, so just
        return the original token again.
        """
        return token

    def authenticate_client(self):
        """
        Authenticate the client issuing the refresh request.

        NOTE: this overrides the method from authlib in order to change the
        checking on the client secret. Fence stores client secrets as hashes,
        so the check on the incoming client secret in the request must be
        changed accordingly.
        """
        client_params = self.parse_basic_auth_header()
        if not client_params:
            raise InvalidClientError(uri=self.uri)

        client_id, client_secret = client_params
        client = self.get_and_validate_client(client_id)

        # Check the hash of the provided client secret against stored hash.
        hashed = client.client_secret
        if bcrypt.hashpw(client_secret, hashed) != hashed:
            raise InvalidClientError(uri=self.uri)

        return client

    def validate_access_token_request(self):
        """
        Check that the refrehs request is valid.

        NOTE: this overrides the method from authlib to do different scope
        checking using the ``access_aud`` field from the refresh token.

        Docs from authlib:

        If the authorization server issued a refresh token to the client, the
        client makes a refresh request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format per Appendix B with a character encoding of UTF-8 in the HTTP
        request entity-body, per Section 6:

        grant_type
            REQUIRED.  Value MUST be set to "refresh_token".

        refresh_token
            REQUIRED.  The refresh token issued to the client.

        scope
            OPTIONAL.  The scope of the access request as described by
            Section 3.3.  The requested scope MUST NOT include any scope
            not originally granted by the resource owner, and if omitted is
            treated as equal to the scope originally granted by the
            resource owner.


        For example, the client makes the following HTTP request using
        transport-layer security (with extra line breaks for display purposes
        only):

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
        """
        # From authlib:
        #
        #     Require client authentication for confidential clients or for any
        #     client that was issued client credentials (or with other
        #     authentication requirements).
        client = self.authenticate_client()
        if not client.check_client_type('confidential'):
            raise UnauthorizedClientError(uri=self.uri)
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(uri=self.uri)
        self._authenticated_client = client

        # Get refresh token from request.
        refresh_token = self.params.get('refresh_token')
        if refresh_token is None:
            raise InvalidRequestError(
                'Missing "refresh_token" in request.',
                uri=self.uri,
            )
        # Validate the refresh token.
        token = self.authenticate_refresh_token(refresh_token)
        if not token:
            raise InvalidRequestError(
                'Invalid "refresh_token" in request.',
                uri=self.uri,
            )
        # Compare the requested scope (which will be stored as audiences in the
        # access token) against the ``access_aud`` field in the refresh token
        # (which stores the audiences allowed to be in the access token).
        scope = self.params.get('scope')
        if scope:
            access_aud = token.get('access_aud')
            if not access_aud:
                raise InvalidScopeError(uri=self.uri)
            access_aud = set(access_aud)
            if not access_aud.issuperset(set(scope)):
                raise InvalidScopeError(uri=self.uri)

        self._authenticated_token = token

    def create_access_token_response(self):
        """
        Create the token response for a refresh request.

        NOTE: this overrides the method from authlib in order to handle the
        scopes differrently (and default the scopes to the ``access_aud``
        field from the refresh token).
        """
        scope = self.params.get('scope')
        if not scope:
            scope = self._authenticated_token['access_aud']
        token = self.token_generator(
            self._authenticated_client, self.GRANT_TYPE, scope=scope,
        )
        self.create_access_token(
            token, self._authenticated_client, self._authenticated_token
        )
        return 200, token, self.TOKEN_RESPONSE_HEADER
