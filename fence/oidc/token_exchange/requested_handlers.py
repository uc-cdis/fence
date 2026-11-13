import flask

from fence.jwt.token import generate_signed_access_token
from fence.models import User
from fence.oidc.errors import OIDCError
from fence.oidc.token_exchange.base import (
    TOKEN_TYPE_ACCESS_TOKEN,
    IssuedToken,
    RequestedTokenHandler,
)
from fence.resources.google.utils import get_linked_google_account_email
from fence.utils import validate_scopes


class AccessTokenRequestedTokenHandler(RequestedTokenHandler):
    """
    Issues a Fence access token.
    """

    def issue(self, user, client, scope, expires_in):
        validate_scopes(scope, client)

        db_session = flask.current_app.scoped_session()
        if user not in db_session:
            user = db_session.query(User).filter_by(id=user.id).first()

        if not user:
            raise OIDCError("subject token did not resolve to a user")

        keypair = flask.current_app.keypairs[0]
        access_token = generate_signed_access_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=user,
            expires_in=expires_in,
            scopes=scope,
            client_id=client.client_id,
            linked_google_email=get_linked_google_account_email(user.id),
        ).token

        return IssuedToken(
            token=access_token,
            issued_token_type=TOKEN_TYPE_ACCESS_TOKEN,
            token_type="Bearer",
            expires_in=expires_in,
            scope=scope,
        )
