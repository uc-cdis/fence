from authlib.common.urls import urlparse, url_decode
from authlib.flask.oauth2 import AuthorizationServer
from authlib.specs.rfc6749.errors import (
    InvalidGrantError,
    InsecureTransportError,
)
import flask

from fence.oidc.jwt_generator import JWTGenerator


class OIDCServer(AuthorizationServer):
    """
    Implement the OIDC provider to attach to the flask app.

    Specific OAuth grants (authorization code, refresh token) are added on to
    a server instance using ``OIDCServer.register_grant_endpoint(grant)``. For
    usage, see ``fence/oidc/server.py``.
    """

    def create_bearer_token_generator(self, app):
        """
        Return an ``authlib.specs.rfc6750.BearerToken`` instance (implemented
        in fence as ``JWTGenerator``) for authlib to use.
        """
        return JWTGenerator()

    def get_authorization_grant(self, uri):
        """
        Find the authorization grant for current request.

        TODO: this overrides the method in authlib to patch a small bug, so we
        can remove this method once the bug is fixed. See:

            https://github.com/lepture/authlib/issues/15

        Args:
            uri (str): HTTP request URI string.

        Return:
            AuthorizationCodeGrant: grant instance for current request
        """
        InsecureTransportError.check(uri)

        # This block patches a bug in authlib.
        if flask.request.method == 'GET':
            params = dict(url_decode(urlparse.urlparse(uri).query))
        elif flask.request.method == 'POST':
            params = flask.request.form.to_dict()
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
