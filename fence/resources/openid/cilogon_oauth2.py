from .idp_oauth2 import Oauth2ClientBase


class CilogonOauth2Client(Oauth2ClientBase):
    """
    client for interacting with CILogon OIDC
    """

    DISCOVERY_URL = "https://cilogon.org/.well-known/openid-configuration"

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(CilogonOauth2Client, self).__init__(
            settings,
            logger,
            scope=settings.get("scope") or "openid email profile",
            idp="CILogon",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", "https://cilogon.org/authorize"
        )

        uri, _ = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        return uri

    def get_auth_info(self, code):
        # use the configured `user_id_field` if there is one, otherwise default to "sub"
        user_id_field = self.settings.get("user_id_field") or "sub"

        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint", "https://cilogon.org/oauth2/token"
            )
            jwks_endpoint = self.get_value_from_discovery_doc(
                "jwks_uri", "https://cilogon.org/oauth2/certs"
            )
            claims, refresh_token, access_token = self.get_jwt_claims_identity(
                token_endpoint, jwks_endpoint, code
            )

            if claims.get(user_id_field):
                return {
                    user_id_field: claims[user_id_field],
                    "sub": claims.get("sub"),
                }
            else:
                return {"error": "Can't get user's CILogon {}".format(user_id_field)}
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your CILogon {}: {}".format(user_id_field, e)}
