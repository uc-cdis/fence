import bcrypt

from authlib.common.security import generate_token
from authlib.specs.rfc6749.errors import (
    InvalidClientError,
    UnauthorizedClientError,
)
from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as AuthlibAuthorizationCodeGrant
)
from authlib.specs.rfc6749.util import get_obj_value
import flask

from fence.models import AuthorizationCode


class AuthorizationCodeGrant(AuthlibAuthorizationCodeGrant):

    def __init__(self, uri, params, headers, client_model, token_generator):
        super(AuthorizationCodeGrant, self).__init__(
            uri, params, headers, client_model, token_generator
        )

    def create_authorization_code(self, client, user, **kwargs):
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
            redirect_uri=kwargs.get('redirect_uri', ''),
            scope=kwargs.get('scope', ''),
            user_id=user.id,
            nonce=kwargs.get('nonce'),
        )

        with flask.current_app.db.session as session:
            session.add(code)
            session.commit()

        return code.code

    def parse_authorization_code(self, code, client):
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

    def delete_authorization_code(self, authorization_code):
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

    def create_access_token(self, token, client, authorization_code):
        """
        Create an "access token" model from the given token.

        The JWTs are stateless, so just pass.
        """
        pass

    def create_access_token_response(self):
        """
        Create the token response.

        NOTE: overrides the method from authlib in order to pass the ``nonce``
        parameter to the token generator.

        Return:
            Tuple[int, dict, dict]: tuple of (status_code, body, headers)
        """
        client = self._authenticated_client
        is_confidential = client.check_client_type('confidential')
        token = self.token_generator(
            client,
            self.GRANT_TYPE,
            scope=get_obj_value(self._authorization_code, 'scope'),
            include_refresh_token=is_confidential,
            nonce=self._authorization_code.nonce,
        )
        self.create_access_token(
            token,
            client,
            self._authorization_code
        )
        self.delete_authorization_code(self._authorization_code)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def authenticate_client(self):
        """Parse the authenticated client.

        For example, the client makes the following HTTP request using TLS:

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
            &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

        To authenticate client with other means, re-implement this method in
        subclass.

        :return: client
        """
        client_params = self.parse_basic_auth_header()
        if client_params:
            # authenticate the client if client authentication is included
            client_id, client_secret = client_params
            client = self.get_and_validate_client(client_id)
            # Client secrets are stored as hash.
            hashed = client.client_secret
            if bcrypt.hashpw(
                    client_secret.encode('utf-8'),
                    hashed.encode('utf-8')) != hashed:
                raise InvalidClientError(uri=self.uri)

            return client

        # require client authentication for confidential clients or for any
        # client that was issued client credentials (or with other
        # authentication requirements)
        client_id = self.params.get('client_id')
        client = self.get_and_validate_client(client_id)
        if client.check_client_type('confidential') or client.client_secret:
            raise UnauthorizedClientError(uri=self.uri)

        return client
