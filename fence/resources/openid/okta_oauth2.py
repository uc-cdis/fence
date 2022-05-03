from .idp_oauth2 import Oauth2ClientBase

OKTA_IDP_NAME = "okta"


class OktaOauth2Client(Oauth2ClientBase):
    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(OktaOauth2Client, self).__init__(
            settings,
            logger,
            scope=settings.get("scope") or "openid email",
            idp="Okta",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint",
            "",
        )
        uri, _ = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        return uri

    def get_user_id(self, code):
        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint",
                "",
            )
            jwks_endpoint = self.get_value_from_discovery_doc(
                "jwks_uri",
                "",
            )
            claims = self.get_jwt_claims_identity(token_endpoint, jwks_endpoint, code)

            if claims.get("email"):
                return {"email": claims["email"], "sub": claims.get("sub")}
            else:
                return {"error": "Can't get user's email!"}
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your email: {}".format(e)}
