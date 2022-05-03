from .idp_oauth2 import Oauth2ClientBase
from fence.config import config


class GoogleOauth2Client(Oauth2ClientBase):
    """
    client for interacting with google oauth 2,
    as google openid connect is supported under oauth2

    https://developers.google.com/api-client-library/python/guide/aaa_oauth
    """

    DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(GoogleOauth2Client, self).__init__(
            settings,
            logger,
            scope=settings.get("scope") or "openid email",
            idp="Google",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", "https://accounts.google.com/o/oauth2/v2/auth"
        )
        uri, _ = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        return uri

    def get_user_id(self, code):
        """
        Get user id
        """
        if config.get("MOCK_GOOGLE_AUTH", False):
            return {"email": "test@gmail.com"}
        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint", "https://oauth2.googleapis.com/token"
            )
            jwks_endpoint = self.get_value_from_discovery_doc(
                "jwks_uri", "https://www.googleapis.com/oauth2/v3/certs"
            )
            claims = self.get_jwt_claims_identity(token_endpoint, jwks_endpoint, code)

            if claims.get("email") and claims.get("email_verified"):
                return {"email": claims["email"], "sub": claims.get("sub")}
            elif claims.get("email"):
                return {"error": "Email is not verified"}
            else:
                return {"error": "Can't get user's Google email!"}

        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your Google email: {}".format(e)}
