from .idp_oauth2 import Oauth2ClientBase


class OrcidOauth2Client(Oauth2ClientBase):
    """
    client for interacting with orcid oauth 2,
    as openid connect is supported under oauth2

    """

    DISCOVERY_URL = "https://orcid.org/.well-known/openid-configuration"

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(OrcidOauth2Client, self).__init__(
            settings,
            logger,
            scope=settings.get("scope") or "openid",
            idp="Orcid",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", "https://orcid.org/oauth/authorize"
        )

        uri, state = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        return uri

    def get_user_id(self, code):
        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint", "https://orcid.org/oauth/token"
            )
            jwks_endpoint = self.get_value_from_discovery_doc(
                "jwks_uri", "https://orcid.org/oauth/jwks"
            )
            claims = self.get_jwt_claims_identity(token_endpoint, jwks_endpoint, code)

            if claims.get("sub"):
                return {"orcid": claims["sub"], "sub": claims["sub"]}
            else:
                return {"error": "Can't get user's orcid"}
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your orcid: {}".format(e)}
