# need new RAS
from .idp_oauth2 import Oauth2ClientBase
from jose import jwt
import requests


class RASOauth2Client(Oauth2ClientBase):
    """
    client for interacting with RAS oauth 2,
    as openid connect is supported under oauth2

    """

    RAS_DISCOVERY_URL = "https://stsstg.nih.gov/.well-known/openid-configuration"

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(RASOauth2Client, self).__init__(
            settings,
            logger,
            scope="openid",
            discovery_url=self.RAS_DISCOVERY_URL,
            idp="ras",
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

    def get_userinfo(self, token, userinfo_endpoint, code):
        header = {"Authorization:" "Bearer " + token}
        res = requests.get(userinfo_endpoint, headers=header)
        return res.json()

    def get_user_id(self, code):
        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            jwks_endpoint = self.get_value_from_discovery_doc("jwks_uri", "")
            userinfo_endpoint = self.get_value_from_discovery_doc(
                "userinfo_endpoint", ""
            )

            token = self.get_token(token_endpoint, code)
            keys = self.get_jwt_keys(jwks_endpoint)

            claims = jwt.decode(
                token["id_token"],
                keys,
                options={"verify_aud": False, "verify_at_hash": False},
            )

            userinfo = self.get_userinfo(token, userinfo_endpoint, code)

            if userinfo["preferred_username"]:
                return {"ras": userinfo["preferred_username"]}
            elif userinfo["UserID"]:
                return {"ras": userinfo["UserID"]}
            elif claims["sub"]:
                return {"ras": claims["sub"]}
            else:
                return {"error": "Can't get user's ras"}
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your ras: {}".format(e)}
