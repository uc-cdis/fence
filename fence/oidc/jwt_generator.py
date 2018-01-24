from authlib.specs.rfc6750.token import BearerToken
import flask

from fence.jwt.token import (
    generate_signed_access_token,
    generate_signed_refresh_token,
)
from fence.user import get_current_user


class JWTGenerator(BearerToken):
    """
    This class implements bearer token generation behavior as required for
    authlib.

    Instances of ``JWTGenerator`` are callables which return the token
    response (see ``__call__``).
    """

    ACCESS_TOKEN_EXPIRES_IN = 1200
    REFRESH_TOKEN_EXPIRES_IN = 28800

    def __init__(self, *args, **kwargs):
        pass

    def __call__(
            self, client, grant_type, expires_in=None, scope=None,
            include_refresh_token=True):
        """
        Generate the token response, which looks like the following:

            {
                'token_type': 'Bearer',
                'access_token': 'eyJhb[...long encoded JWT...]evfxA',
                'refresh_token': 'eyJhb[ ... long encoded JWT ... ]KnLJA',
                'expires_in': 1200,
            }

        This function will be called in authlib internals.

        Args:
            client: not used (would be used to determine expiration)
            grant_type: not used
        """

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
        # ``expires_in`` is just the access token expiration time.
        expires_in = self.ACCESS_TOKEN_EXPIRES_IN
        return {
            'token_type': 'Bearer',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': expires_in,
        }
