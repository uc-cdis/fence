"""
Define the authorization server. It must later be initialized onto a Flask app:

.. code-block:: python

    server.init_app(app)
"""

from fence.jwt.server import JWTAuthServer
from fence.oauth2.grants import AuthorizationCodeGrant
from fence.models import Client


server = JWTAuthServer(Client)
server.register_grant_endpoint(AuthorizationCodeGrant)
