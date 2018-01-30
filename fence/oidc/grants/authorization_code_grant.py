import bcrypt

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.specs.rfc6749.errors import (
    AccessDeniedError,
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    UnauthorizedClientError,
)
from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as AuthlibAuthorizationCodeGrant
)
import flask

from fence.models import AuthorizationCode


class AuthorizationCodeGrant(AuthlibAuthorizationCodeGrant):

    def __init__(self, uri, params, headers, client_model, token_generator):
        super(AuthorizationCodeGrant, self).__init__(
            uri, params, headers, client_model, token_generator
        )

    def create_authorization_code(self, client, user, **kwargs):
        code = AuthorizationCode(
            code=generate_token(50),
            client_id=client.client_id,
            redirect_uri=kwargs.get('redirect_uri', ''),
            scope=kwargs.get('scope', ''),
            user_id=user.id,
        )

        with flask.current_app.db.session as session:
            session.add(code)
            session.commit()

        return code.code

    def parse_authorization_code(self, code, client):
        with flask.current_app.db.session as session:
            code = (
                session.query(AuthorizationCode)
                .filter_by(code=code, client_id=client.client_id)
                .first()
            )
        if not code or code.is_expired():
            return None
        return code

    def delete_authorization_code(self, authorization_code):
        with flask.current_app.db.session as session:
            session.delete(authorization_code)
            session.commit()

    def create_access_token(self, token, client, authorization_code):
        pass

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
            if bcrypt.hashpw(client_secret, hashed) != hashed:
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
