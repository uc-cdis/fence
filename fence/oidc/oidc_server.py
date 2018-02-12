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
