import json

from .idp_oauth2 import Oauth2ClientBase


class SynapseOauth2Client(Oauth2ClientBase):
    """
    client for interacting with Synapse OAuth2,
    as OpenID Connect is supported under OAuth2

    """

    ISSUER = "https://www.synapse.org/auth/v1"
    REQUIRED_CLAIMS = {"give_name", "family_name", "email"}
    OPTIONAL_CLAIMS = {"company"}
    SYSTEM_CLAIMS = {"sub", "exp"}
    CUSTOM_CLAIMS = {"team"}

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(SynapseOauth2Client, self).__init__(
            settings,
            logger,
            scope="openid",
            discovery_url=self.ISSUER + "/.well-known/openid-configuration",
            idp="Synapse",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", self.ISSUER + "/oauth2/authorize"
        )

        claims = dict(
            id_token=dict(
                team=dict(values=["1"]),
                **{
                    claim: dict(essential=claim in self.REQUIRED_CLAIMS)
                    for claim in self.REQUIRED_CLAIMS | self.OPTIONAL_CLAIMS
                }
            )
        )
        uri, state = self.session.create_authorization_url(
            authorization_endpoint,
            prompt="login",
            claims=json.dumps(claims, separators=(",", ": ")),
        )

        return uri

    def get_user_id(self, code):
        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint", self.ISSUER + "/oauth2/token"
            )
            jwks_endpoint = self.get_value_from_discovery_doc(
                "jwks_uri", self.ISSUER + "/oauth2/jwks"
            )
            claims = self.get_jwt_claims_identity(token_endpoint, jwks_endpoint, code)

            if not claims["email_verified"]:
                return dict(error="Email is not verified")

            rv = {}
            for claim in (
                self.REQUIRED_CLAIMS
                | self.OPTIONAL_CLAIMS
                | self.SYSTEM_CLAIMS
                | self.CUSTOM_CLAIMS
            ):
                if claim not in self.OPTIONAL_CLAIMS and claim not in claims:
                    return dict(error="Required claim {} not found".format(claim))
                rv[claim] = claims[claim]
            return rv
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get ID token: {}".format(e)}
