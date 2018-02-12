import bcrypt

from authlib.specs.rfc6749.errors import InvalidClientError
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

    NOTE: ``self._authenticated_token`` is the refresh token claims as a
    dictionary; ``self.params['refresh_token']`` is the actual string.
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
        if bcrypt.hashpw(
                client_secret.encode('utf-8'),
                hashed.encode('utf-8')) != hashed:
            raise InvalidClientError(uri=self.uri)

        return client

    def create_access_token_response(self):
        """
        Docs from authlib:

            If valid and authorized, the authorization server issues an access
            token as described in Section 5.1. If the request failed
            verification or is invalid, the authorization server returns an
            error response as described in Section 5.2.
        """
        scope = self.params.get('scope')
        if not scope:
            scope = self._authenticated_token['aud']

        token = self.token_generator(
            client=self._authenticated_client,
            grant_type=self.GRANT_TYPE,
            scope=scope,
            refresh_token=self.params.get('refresh_token'),
            refresh_token_claims=self._authenticated_token,
        )
        self.create_access_token(
            token,
            self._authenticated_client,
            self._authenticated_token
        )
        return 200, token, self.TOKEN_RESPONSE_HEADER
