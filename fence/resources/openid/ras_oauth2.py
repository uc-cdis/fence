import flask
import requests
import jwt
import backoff
import json
from flask_sqlalchemy_session import current_session
from jose import jwt as jose_jwt

from fence.models import GA4GHVisaV1
from fence.utils import DEFAULT_BACKOFF_SETTINGS
from .idp_oauth2 import Oauth2ClientBase


class RASOauth2Client(Oauth2ClientBase):
    """
    client for interacting with RAS oauth 2,
    as openid connect is supported under oauth2
    """

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(RASOauth2Client, self).__init__(
            settings,
            logger,
            scope="openid ga4gh_passport_v1 email profile",
            discovery_url=settings.get(
                "discovery_url", "https://sts.nih.gov/.well-known/openid-configuration"
            ),
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

    def validate_passport(self, validation_endpoint, passport):
        """
        Validate passport with RAS's validation endpoint.
        TODO: Remove this once we can locally validate passports
        NOTE: RAS has an option to query a single visa with the /passport/validate?visa= but not using these since we hit the limit for an http header pretty quick
        """
        payload = json.dumps(passport)
        headers = {"Content-Type": "application/json"}
        res = requests.post(validation_endpoint, headers=headers, data=payload)
        return res.text.encode("utf8")

    def get_user_id(self, code):

        err_msg = "Can't get user's info"

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            jwks_endpoint = self.get_value_from_discovery_doc("jwks_uri", "")
            userinfo_endpoint = self.get_value_from_discovery_doc(
                "userinfo_endpoint", ""
            )
            validation_endpoint = (
                self.get_value_from_discovery_doc("issuer", "") + "/passport/validate"
            )

            token = self.get_token(token_endpoint, code)
            keys = self.get_jwt_keys(jwks_endpoint)
            userinfo = self.get_userinfo(token, userinfo_endpoint)

            validation = self.validate_passport(validation_endpoint, userinfo)

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
            flask.g.userinfo = userinfo if validation == "Valid" else {}
            flask.g.tokens = token

        except Exception as e:
            self.logger.exception("{}: {}".format(err_msg, e))
            return {"error": err_msg}

        return {"username": username}

    @backoff.on_exception(backoff.expo, Exception, **DEFAULT_BACKOFF_SETTINGS)
    def update_user_visas(self, user):
        """
        Updates user's RAS refresh token and uses the new access token to retrieve new visas from
        RAS's /userinfo endpoint and update the db with the new visa.
        - delete user's visas from db if we're not able to get a new access_token
        - delete user's visas from db if we're not able to get a new visa
        """
        user.ga4gh_visas_v1 = []
        current_session.commit()

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            userinfo_endpoint = self.get_value_from_discovery_doc(
                "userinfo_endpoint", ""
            )
            token = self.get_access_token(user, token_endpoint)
            userinfo = self.get_userinfo(token, userinfo_endpoint)
        except Exception as e:
            err_msg = "Could not retrieve visa"
            self.logger.exception("{}: {}".format(err_msg, e))
            raise

        validation_endpoint = (
            self.get_value_from_discovery_doc("issuer", "") + "/passport/validate"
        )
        validation = self.validate_passport(validation_endpoint, userinfo)
        encoded_visas = (
            userinfo.get("ga4gh_passport_v1", []) if validation == "Valid" else []
        )
        # TODO: add logs for visa validation

        for encoded_visa in encoded_visas:
            try:
                # TODO: These visas must be validated!!!
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
            except Exception as e:
                err_msg = (
                    f"Could not process visa '{encoded_visa}' - skipping this visa"
                )
                self.logger.exception("{}: {}".format(err_msg, e), exc_info=True)
            current_session.commit()
