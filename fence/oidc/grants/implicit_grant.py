from authlib.specs.oidc.grants import OpenIDImplicitGrant
from authlib.specs.oidc.grants.base import create_response_mode_response
from authlib.specs.rfc6749 import AccessDeniedError, InvalidRequestError
import flask

from fence.models import AuthorizationCode


class ImplicitGrant(OpenIDImplicitGrant):
    def validate_nonce(self, required=False):
        """
        Override method in authlib to skip adding ``exists_nonce`` hook on server. I
        don't think this needs to exist according to OIDC spec but this stays consistent
        with authlib so here we are
        """
        return True

    def create_authorization_response(self, grant_user):
        """
        Overrides method from authlib---authlib has some peculiarities here such as
        trying to access ``token["scope"]`` from the token response which is not
        following OIDC. This should be creating a response in accordance with the spec
        here:

        https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
        """
        state = self.request.state
        if grant_user:
            self.request.user = grant_user
            client = self.request.client
            include_access_token = self.request.response_type == "id_token token"
            token_response = self.generate_token(
                client,
                self.GRANT_TYPE,
                include_access_token=include_access_token,
                user=grant_user,
                scope=self.request.scope,
            )
            params = [(k, token_response[k]) for k in token_response]
            if state:
                params.append(("state", state))
        else:
            error = AccessDeniedError(state=state)
            params = error.get_body()

        # http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
        return create_response_mode_response(
            redirect_uri=self.redirect_uri,
            params=params,
            response_mode=self.request.response_mode,
        )

    def generate_token(self, *args, **kwargs):
        return self.server.generate_token(*args, **kwargs)
