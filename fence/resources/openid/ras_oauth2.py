import flask
from .idp_oauth2 import Oauth2ClientBase
from jose import jwt as jose_jwt
import requests
import jwt
from fence.models import GA4GHVisaV1
from flask_sqlalchemy_session import current_session


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
            scope="openid ga4gh_passport_v1 email profile",
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

    def get_userinfo(self, token, userinfo_endpoint):
        access_token = token["access_token"]
        header = {"Authorization": "Bearer " + access_token}
        res = requests.get(userinfo_endpoint, headers=header)
        return res.json()

    def get_user_id(self, code):

        err_msg = "Can't get user's info"

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            jwks_endpoint = self.get_value_from_discovery_doc("jwks_uri", "")
            userinfo_endpoint = self.get_value_from_discovery_doc(
                "userinfo_endpoint", ""
            )

            token = self.get_token(token_endpoint, code)
            keys = self.get_jwt_keys(jwks_endpoint)
            userinfo = self.get_userinfo(token, userinfo_endpoint)

            claims = jose_jwt.decode(
                token["id_token"],
                keys,
                options={"verify_aud": False, "verify_at_hash": False},
            )

            username = None
            if userinfo.get("UserID"):
                username = userinfo["UserID"]
                field_name = "UserID"
            elif userinfo.get("preferred_username"):
                username = userinfo["preferred_username"]
                field_name = "preferred_username"
            elif claims.get("sub"):
                username = claims["sub"]
                field_name = "sub"
            if not username:
                self.logger.error(
                    "{}, received claims: {} and userinfo: {}".format(
                        err_msg, claims, userinfo
                    )
                )
                return {"error": err_msg}

            self.logger.info("Using {} field as username.".format(field_name))

            # Save userinfo and token in flask.g for later use in post_login
            flask.g.userinfo = userinfo
            flask.g.tokens = token

        except Exception as e:
            self.logger.exception("{}: {}".format(err_msg, e))
            return {"error": err_msg}

        return {"username": username}

    def update_visa(self, user):

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            userinfo_endpoint = self.get_value_from_discovery_doc(
                "userinfo_endpoint", ""
            )
            token = self.get_access_token(user, token_endpoint)
            userinfo = self.get_userinfo(token, userinfo_endpoint)
            encoded_visas = userinfo.get("ga4gh_passport_v1", [])
            user.ga4gh_visas_v1 = []

            for encoded_visa in encoded_visas:
                decoded_visa = jwt.decode(encoded_visa, verify=False)
                visa = GA4GHVisaV1(
                    user=user,
                    source=decoded_visa["ga4gh_visa_v1"]["source"],
                    type=decoded_visa["ga4gh_visa_v1"]["type"],
                    asserted=int(decoded_visa["ga4gh_visa_v1"]["asserted"]),
                    expires=int(decoded_visa["exp"]),
                    ga4gh_visa=encoded_visa,
                )

                current_db_session = current_session.object_session(visa)

                current_db_session.add(visa)
                current_session.commit()
        except Exception as e:
            err_msg = "Could not update visa"
            self.logger.exception("{}: {}".format(err_msg, e))
