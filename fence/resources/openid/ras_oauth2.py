#need new RAS
from .idp_oauth2 import Oauth2ClientBase


class RASOauth2Client(Oauth2ClientBase):
    """
    client for interacting with orcid oauth 2,
    as openid connect is supported under oauth2

    """

    RAS_DISCOVERY_URL = "https://stsstg.nih.gov/.well-known/openid-configuration"

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(RASOauth2Client, self).__init__(
            settings,
            logger,
            scope="openid",
            discovery_url=self.RAS_DISCOVERY_URL,
            idp="RAS",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", ""
        )

        uri, state = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        return uri

    def get_user_id(self, code):
        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint", ""
            )
            jwks_endpoint = self.get_value_from_discovery_doc(
                "jwks_uri", ""
            )
            claims = self.get_jwt_claims_identity(token_endpoint, jwks_endpoint, code)

            if claims["sub"]:
                return {"orcid": claims["sub"]}
            else:
                return {"error": "Can't get user's orcid"}
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your orcid: {}".format(e)}
