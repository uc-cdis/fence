"""
Define the authorization server. It must later be initialized onto a Flask app:

.. code-block:: python

    server.init_app(app)
"""

from fence.models import Client
from fence.oidc.endpoints import RevocationEndpoint
from fence.oidc.grants import AuthorizationCodeGrant, RefreshTokenGrant
from fence.oidc.oidc_server import OIDCServer


server = OIDCServer(Client)
server.register_grant_endpoint(AuthorizationCodeGrant)
server.register_grant_endpoint(RefreshTokenGrant)
server.register_revoke_token_endpoint(RevocationEndpoint)
