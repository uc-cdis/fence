import flask

from fence.oidc.errors import InvalidClientError
from fence.oidc.jwt_generator import generate_token

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749.authenticate_client import (
    ClientAuthentication as AuthlibClientAuthentication,
)

from authlib.oauth2.rfc6749.errors import (
    InvalidClientError as AuthlibClientError,
    OAuth2Error,
    UnsupportedGrantTypeError,
)

from fence import logger
from cdislogging import get_logger
from flask.wrappers import Request
from authlib.oauth2.rfc6749 import OAuth2Request

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
                    "Confidential OAuth client failed to authenticate; client ID or secret is"
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

    # 2023-09-29
    # Below code replaces authlib functions. It does the same thing as authlib 1.2.1 except it returns grant_scope from
    # either args or forms. Authlib 1.2.1 forces grant_type to be part of post request body which isn't the current use case.
    # https://github.com/lepture/authlib/blob/a6e89f8e6cf6f6bebd63dcdc2665b7d22cf0fde3/authlib/oauth2/rfc6749/requests.py#L59C10-L59C10
    def create_token_response(self, request=None):
        """Validate token request and create token response.

        Args:
            request: HTTP request instance
        Returns:
            HTTP response with token
        """
        request = self.create_oauth2_request(request)

        try:
            grant = self.get_token_grant(request)
        except UnsupportedGrantTypeError as error:
            return self.handle_error_response(request, error)

        logger.debug("Got grant succesfully")

        try:
            grant.validate_token_request()
            logger.debug("Token Request validated succesfully")
            args = grant.create_token_response()
            logger.debug("Token created succesfully")
            return self.handle_response(*args)
        except OAuth2Error as error:
            return self.handle_error_response(request, error)

    def create_oauth2_request(self, request):
        return FenceOAuth2Request(flask.request)


class FenceOAuth2Request(OAuth2Request):
    def __init__(self, request: Request):
        super().__init__(request.method, request.url, None, request.headers)
        self._request = request

    @property
    def args(self):
        return self._request.args

    @property
    def form(self):
        return self._request.values

    # Get grant_type from either url or body
    @property
    def grant_type(self) -> str:
        return self.data.get("grant_type")
