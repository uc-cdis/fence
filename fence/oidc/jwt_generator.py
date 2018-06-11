from authlib.specs.rfc6750.token import BearerToken
import flask
from flask_sqlalchemy_session import current_session

from fence.jwt.token import (
    generate_signed_access_token,
    generate_signed_id_token,
    generate_signed_refresh_token,
)
from fence.models import AuthorizationCode, User
from fence.resources.google.utils import get_linked_google_account_email

import fence.settings


class JWTGenerator(BearerToken):
    """
    Implement bearer token generation behavior as required for authlib.

    Instances of ``JWTGenerator`` are callables which return the token
    response (see ``__call__``).
    """

    ACCESS_TOKEN_EXPIRES_IN = fence.settings.ACCESS_TOKEN_EXPIRES_IN
    REFRESH_TOKEN_EXPIRES_IN = fence.settings.REFRESH_TOKEN_EXPIRES_IN

    def __init__(self, *args, **kwargs):
        pass

    def __call__(
            self, client, grant_type, expires_in=None, scope=None,
            include_refresh_token=True, nonce=None, refresh_token=None,
            refresh_token_claims=None):
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
            expires_in: not used (see expiration times configured above)
            scope (List[str]): list of requested scopes
            include_refresh_token: not used
            nonce (str): "nonsense" to include in ID token (see OIDC spec)
            refresh_token:
                for a refresh token grant, pass in the previous refresh token
                to return that same token again instead of generating a new one
                (otherwise this will let the refresh token refresh itself)
            refresh_token_claims (dict):
                also for a refresh token grant, pass the previous refresh token
                claims (to avoid having to encode or decode the refresh token
                here)
        """
        # Find the ``User`` model.
        # The way to do this depends on the grant type.
        user = None
        if grant_type == 'authorization_code':
            # For authorization code grant, get the code from either the query
            # string or the form data, and use that to look up the user.
            if flask.request.method == 'GET':
                code = flask.request.args.get('code')
            else:
                code = flask.request.form.get('code')
            user = (
                current_session
                .query(AuthorizationCode)
                .filter_by(code=code)
                .first()
                .user
            )
        if grant_type == 'refresh_token':
            # For refresh token, the user ID is the ``sub`` field in the token.
            user = (
                current_session
                .query(User)
                .filter_by(id=int(refresh_token_claims['sub']))
                .first()
            )

        keypair = flask.current_app.keypairs[0]

        linked_google_email = get_linked_google_account_email(user.id)

        id_token = generate_signed_id_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=user,
            expires_in=self.ACCESS_TOKEN_EXPIRES_IN,
            client_id=client.client_id,
            audiences=scope,
            nonce=nonce,
            linked_google_email=linked_google_email
        )
        access_token = generate_signed_access_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=user,
            expires_in=self.ACCESS_TOKEN_EXPIRES_IN,
            scopes=scope,
            client_id=client.client_id,
            linked_google_email=linked_google_email
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
                client_id=client.client_id,
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
