from idp_oauth2 import Oauth2ClientBase


class ElixirOauth2Client(Oauth2ClientBase):
    """
    client for interacting with elixir oauth 2,
    as openid connect is supported under oauth2

    Docs at https://docs.google.com/document/u/1/d/1vOyW4dLVozy7oQvINYxHheVaLvwNsvvghbiKTLg7RbY/edit#

    """

    ELIXIR_DISCOVERY_URL = "https://login.elixir-czech.org/oidc/.well-known/openid-configuration"

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(ElixirOauth2Client, self).__init__(
            settings,
            logger,
            scope="openid email bona_fide_status",
            discovery_url=self.ELIXIR_DISCOVERY_URL,
            idp="Elixir",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint",
            "https://login.elixir-czech.org/oidc/authorize",
        )
        uri, _ = self.session.authorization_url(authorization_endpoint)

        return uri

    def get_user_id(self, code):
        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint",
                "https://login.elixir-czech.org/oidc/token",
            )
            jwks_endpoint = self.get_value_from_discovery_doc(
                "jwks_uri",
                "https://login.elixir-czech.org/oidc/jwk",
            )
            userinfo_endpoint = self.get_value_from_discovery_doc(
                "userinfo_endpoint",
                "https://login.elixir-czech.org/oidc/userinfo",
            )
            claims = self.get_jwt_userinfo_identity(token_endpoint, jwks_endpoint, userinfo_endpoint, code)

            if claims["email"]:
                return {"email": claims["email"]}
            else:
                return {"error": "Can't get user's Elixir email!"}
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your Elixir email: {}".format(e)}
