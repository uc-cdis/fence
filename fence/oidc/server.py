"""
Define the authorization server. It must later be initialized onto a Flask app:

.. code-block:: python

    server.init_app(app)
"""

from fence.oidc.client import authenticate_public_client, query_client
from fence.oidc.endpoints import RevocationEndpoint
from fence.oidc.grants import (
    AuthorizationCodeGrant,
    ImplicitGrant,
    RefreshTokenGrant,
    ClientCredentialsGrant,
    TokenExchangeGrant,
)
from fence.oidc.oidc_server import OIDCServer


server = OIDCServer(query_client=query_client, save_token=lambda *_: None)
server.register_grant(AuthorizationCodeGrant)
server.register_grant(ImplicitGrant)
server.register_grant(RefreshTokenGrant)
server.register_grant(ClientCredentialsGrant)
# the grant itself checks whether TOKEN_EXCHANGE is enabled, since config is not
# loaded when this module is imported
server.register_grant(TokenExchangeGrant)
server.register_endpoint(RevocationEndpoint)
server.register_client_auth_method("none", authenticate_public_client)
