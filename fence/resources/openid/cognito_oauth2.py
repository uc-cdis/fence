import json
from .idp_oauth2 import Oauth2ClientBase


class CognitoOauth2Client(Oauth2ClientBase):
    """
    Amazon Cognito OIDC client
    https://docs.aws.amazon.com/cognito/index.html

    At time of writing, the Cognito issuer/auth/jwks/token endpoints and
    discovery url do not follow the standard OIDC patterns. Furthermore they
    depend on the user pool name/ID (and therefore cannot be hardcoded).
    So, just pass "" as default values to get_value_from_discovery_doc
    and log error when necessary.
    """

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(CognitoOauth2Client, self).__init__(
            settings,
            logger,
            scope=settings.get("scope") or "openid email",
            idp="Amazon Cognito",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization endpoint from discovery doc
        and construct authorization url
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", ""
        )
        uri, state = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        return uri

    def get_user_id(self, code):
        """
        Exchange code for tokens, get email from id token claims.
        Return dict with "email" field on success OR "error" field on error.
        """
        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            jwks_endpoint = self.get_value_from_discovery_doc("jwks_uri", "")
            claims = self.get_jwt_claims_identity(token_endpoint, jwks_endpoint, code)

            self.logger.info(f"Received id token from Cognito: {claims}")

            if claims.get("email") and (
                claims.get("email_verified")
                or self.settings.get("assume_emails_verified")
            ):
                return {"email": claims["email"], "sub": claims.get("sub")}
            elif claims.get("email"):
                return {"error": "Email is not verified"}
            else:
                return {"error": "Can't get email from claims"}

        except Exception as e:
            self.logger.exception("Can't get user info from Cognito")
            return {"error": "Can't get user info from Cognito: {}".format(e)}
