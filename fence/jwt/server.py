from authlib.flask.oauth2 import AuthorizationServer
from authlib.specs.rfc6750.token import BearerToken
import flask

from fence.jwt.token import (
    generate_signed_access_token,
    generate_signed_refresh_token,
)
from fence.user import get_current_user


class JWT(BearerToken):

    ACCESS_TOKEN_EXPIRES_IN = 1200
    REFRESH_TOKEN_EXPIRES_IN = 28800

    def __init__(self):
        pass

    def __call__(
            self, client, grant_type, expires_in=None, scope=None,
            include_refresh_token=True):

        keypair = flask.current_app.keypairs[0]
        access_token = generate_signed_access_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=get_current_user(),
            expires_in=self.ACCESS_TOKEN_EXPIRES_IN,
            scopes=scope,
        )
        refresh_token = generate_signed_refresh_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=get_current_user(),
            expires_in=self.REFRESH_TOKEN_EXPIRES_IN,
            scopes=scope,
        )

        return {
            'token_type': 'Bearer',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': expires_in,
        }

class JWTAuthServer(AuthorizationServer):

    def create_bearer_token_generator(self, app):

        return JWT()
