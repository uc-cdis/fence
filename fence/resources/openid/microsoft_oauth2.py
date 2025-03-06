from .idp_oauth2 import Oauth2ClientBase


class MicrosoftOauth2Client(Oauth2ClientBase):
    """
    client for interacting with microsoft oauth 2,
    as openid connect is supported under oauth2

    Docs at https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc

    """

    DISCOVERY_URL = "https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration"

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(MicrosoftOauth2Client, self).__init__(
            settings,
            logger,
            scope=settings.get("scope") or "openid email",
            idp="Microsoft",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint",
            "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
        )
        uri, _ = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        return uri

    def get_auth_info(self, code):
        """
        Get user id given an authorization code
        """
        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint",
                "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
            )
            jwks_endpoint = self.get_value_from_discovery_doc(
                "jwks_uri",
                "https://login.microsoftonline.com/organizations/discovery/v2.0/keys",
            )
            claims, refresh_token, access_token = self.get_jwt_claims_identity(
                token_endpoint, jwks_endpoint, code
            )

            if claims.get("email"):
                return {"email": claims["email"], "sub": claims.get("sub")}
            return {"error": "Can't get user's Microsoft email!"}
        except Exception as exception:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your Microsoft email: {}".format(exception)}
