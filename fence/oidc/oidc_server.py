import flask

from fence.oidc.errors import InvalidClientError
from fence.oidc.jwt_generator import generate_token

from authlib.common.urls import urlparse, url_decode
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749.authenticate_client import (
    ClientAuthentication as AuthlibClientAuthentication,
)

from authlib.oauth2.rfc6749.errors import (
    InvalidClientError as AuthlibClientError,
    OAuth2Error,
    UnsupportedGrantTypeError,
)
from authlib.integrations.flask_oauth2.requests import FlaskOAuth2Request

from fence import logger
from cdislogging import get_logger
from flask.wrappers import Request
from authlib.oauth2.rfc6749 import OAuth2Request, JsonRequest

logger = get_logger(__name__)


class ClientAuthentication(AuthlibClientAuthentication):
    """
    For authlib implementation---this class is a callable that goes on the OIDC server
    in order to authenticate OAuth clients.
    """

    def authenticate(self, request, methods, endpoint):
        """
        Override method from authlib
        """
        client = super(ClientAuthentication, self).authenticate(
            request, methods, endpoint
        )
        # don't allow confidential clients to not use auth
        if client.is_confidential:
            m = list(methods)
            if "none" in m:
                m.remove("none")
            try:
                client = super(ClientAuthentication, self).authenticate(
                    request, m, endpoint
                )
            except AuthlibClientError:
                raise InvalidClientError(
                    "OAuth client failed to authenticate; client ID or secret is"
                    " missing or incorrect"
                )
        return client


class OIDCServer(AuthorizationServer):
    """
    Implement the OIDC provider to attach to the flask app.

    Specific OAuth grants (authorization code, refresh token, etc) are added
    on to a server instance using ``OIDCServer.register_grant(grant)``. For
    usage, see ``fence/oidc/server.py``.
    """

    def init_app(self, app, query_client=None, save_token=None):
        if query_client is not None:
            self.query_client = query_client
        if save_token is not None:
            self.save_token = save_token
        self.app = app
        self.generate_token = generate_token
        if getattr(self, "query_client"):
            self.authenticate_client = ClientAuthentication(query_client)

    def create_token_response(self, request=None):
        """Validate token request and create token response.

        :param request: HTTP request instance
        """
        request = self.create_oauth2_request(request)

        try:
            grant = self.get_token_grant(request)
        except UnsupportedGrantTypeError as error:
            return self.handle_error_response(request, error)

        try:
            grant.validate_token_request()
            args = grant.create_token_response()
            return self.handle_response(*args)
        except OAuth2Error as error:
            return self.handle_error_response(request, error)

    def create_oauth2_request(self, request):
        logger.debug("Creating Oauth2 Request. Logging flask request vars")
        for key in flask.request.values.keys():
            logger.debug(key + " : " + flask.request.values[key])

        oauth_request = FlaskOAuth2Request(flask.request)

        logger.debug("Logging Created Oauth2 Request variables")
        if oauth_request.grant_type:
            logger.debug("request.grant_type:" + oauth_request.grant_type)
        else:
            logger.debug("request.grant_type is None")

        logger.debug("request.method:" + oauth_request.method)
        return oauth_request


class FenceOauth2Request(FlaskOAuth2Request):
    def __init__(self, request: Request):
        logger.debug("logging pre constructor")
        for key in request.values.keys():
            logger.debug(key + " : " + request.values[key])

        super().__init__(request.method, request.url, None, request.headers)
        self._request = request

        logger.debug("logging post constructor")
        for key in self.values.keys():
            logger.debug(key + " : " + self.data[key])

        if self.grant_type:
            logger.debug("request.grant_type:" + self.grant_type)
        else:
            logger.debug("request.grant_type is None")

    @property
    def args(self):
        return self._request.args

    @property
    def form(self):
        return self._request.form

    @property
    def data(self):
        return self._request.values
