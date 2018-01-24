from authlib.common.urls import urlparse, url_decode
from authlib.flask.oauth2 import AuthorizationServer
from authlib.specs.rfc6749.errors import (
    InvalidGrantError,
    InsecureTransportError,
)
import flask

from fence.oidc.jwt_generator import JWTGenerator


class OIDCServer(AuthorizationServer):

    def create_bearer_token_generator(self, app):
        return JWTGenerator()

    def get_authorization_grant(self, uri):
        """
        Find the authorization grant for current request.

        Args:
            uri (str): HTTP request URI string.

        Return:
            AuthorizationCodeGrant: grant instance
        """
        InsecureTransportError.check(uri)

        # This patches a bug in authlib
        if flask.request.method == 'GET':
            params = dict(url_decode(urlparse.urlparse(uri).query))
        elif flask.request.method == 'POST':
            params = flask.request.form
        else:
            raise ValueError('invalid request method')

        for grant_cls in self._authorization_endpoints:
            if grant_cls.check_authorization_endpoint(params):
                return grant_cls(
                    uri, params, {},
                    self.client_model,
                    self.token_generator
                )

        raise InvalidGrantError()
