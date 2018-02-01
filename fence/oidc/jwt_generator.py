from authlib.specs.rfc6750.token import BearerToken
import flask

from fence.jwt.token import (
    generate_signed_access_token,
    generate_signed_id_token,
    generate_signed_refresh_token,
)
from fence.user import get_current_user


class JWTGenerator(BearerToken):
    """
    Implement bearer token generation behavior as required for authlib.

    Instances of ``JWTGenerator`` are callables which return the token
    response (see ``__call__``).
    """

    ACCESS_TOKEN_EXPIRES_IN = 1200
    REFRESH_TOKEN_EXPIRES_IN = 1728000

    def __init__(self, *args, **kwargs):
        pass

    def __call__(
            self, client, grant_type, expires_in=None, scope=None,
            include_refresh_token=True, refresh_token=None):
        """
        Generate the token response, which looks like the following:

            {
                'token_type': 'Bearer',
                'id_token': 'eyJhb[...long encoded JWT...]OnoVQ',
                'access_token': 'eyJhb[...long encoded JWT...]evfxA',
                'refresh_token': 'eyJhb[ ... long encoded JWT ... ]KnLJA',
                'expires_in': 1200,
            }

        This function will be called in authlib internals.

        Args:
            client: not used (would be used to determine expiration)
            grant_type: not used
            ...
            refresh_token:
                for a refresh token grant, pass in the previous refresh token
                to return that same token again instead of generating a new one
        """

        user = get_current_user()
        keypair = flask.current_app.keypairs[0]
        id_token = generate_signed_id_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=user,
            expires_in=self.ACCESS_TOKEN_EXPIRES_IN,
            client_id=client.client_id,
            audiences=scope,
        )
        access_token = generate_signed_access_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=user,
            expires_in=self.ACCESS_TOKEN_EXPIRES_IN,
            scopes=scope,
        )
        # If ``refresh_token`` was passed (for instance from the refresh
        # grant), use that instead of generating a new one.
        if refresh_token is None:
            refresh_token, _ = generate_signed_refresh_token(
                kid=keypair.kid,
                private_key=keypair.private_key,
                user=user,
                expires_in=self.REFRESH_TOKEN_EXPIRES_IN,
                scopes=scope,
            )
        # ``expires_in`` is just the access token expiration time.
        expires_in = self.ACCESS_TOKEN_EXPIRES_IN
        return {
            'token_type': 'Bearer',
            'id_token': id_token,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': expires_in,
        }
