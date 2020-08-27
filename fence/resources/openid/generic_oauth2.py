import json
from .idp_oauth2 import Oauth2ClientBase

GENERIC_IDP_NAME = "generic"

class GenericOauth2Client(Oauth2ClientBase):
    
    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(GenericOauth2Client, self).__init__(
            settings,
            logger,
            scope="openid email",
            discovery_url=settings["discovery_url"],
            idp="Generic",
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

            if claims["email"]:
                return {"email": claims["email"]}
            else:
                return {"error": "Can't get user's email!"}
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your email: {}".format(e)}
