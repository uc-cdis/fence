"""
Define the authorization server. It must later be initialized onto a Flask app:

.. code-block:: python

    server.init_app(app)
"""

from fence.oidc.client import authenticate_public_client, query_client
from fence.oidc.endpoints import IntrospectionEndpoint, RevocationEndpoint
from fence.oidc.grants import (
    AuthorizationCodeGrant,
    ImplicitGrant,
    RefreshTokenGrant,
    ClientCredentialsGrant,
)
from fence.oidc.oidc_server import OIDCServer
from fence.oidc.private_key_jwt import FencePrivateKeyJWT


server = OIDCServer(query_client=query_client, save_token=lambda *_: None)
server.register_grant(AuthorizationCodeGrant)
server.register_grant(ImplicitGrant)
server.register_grant(RefreshTokenGrant)
server.register_grant(ClientCredentialsGrant)
server.register_endpoint(RevocationEndpoint)
server.register_endpoint(IntrospectionEndpoint)
server.register_client_auth_method("none", authenticate_public_client)
server.register_client_auth_method("private_key_jwt", FencePrivateKeyJWT())
