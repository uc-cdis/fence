import flask
import jwt
import os

# the whole fence_create module is imported to avoid issues with circular imports
import fence.scripting.fence_create
from distutils.util import strtobool
from urllib.parse import urlparse, parse_qs

from cdislogging import get_logger
from flask import current_app
from gen3authz.client.arborist.client import ArboristClient

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback
from fence.config import config
from fence.errors import InternalError
from fence.models import IdentityProvider
from fence.utils import get_valid_expiration
import fence.resources.ga4gh.passports


logger = get_logger(__name__)
PKEY_CACHE = {}


class RASLogin(DefaultOAuth2Login):
    def __init__(self):
        super(RASLogin, self).__init__(
            idp_name=IdentityProvider.ras, client=flask.current_app.ras_client
        )


class RASCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(RASCallback, self).__init__(
            idp_name=IdentityProvider.ras,
            client=flask.current_app.ras_client,
            username_field="username",
        )

    def post_login(self, user=None, token_result=None, id_from_idp=None):
        parsed_url = urlparse(flask.session.get("redirect"))
        query_params = parse_qs(parsed_url.query)

        userinfo = flask.g.userinfo

        global_parse_visas_on_login = config["GLOBAL_PARSE_VISAS_ON_LOGIN"]
        parse_visas = global_parse_visas_on_login or (
            global_parse_visas_on_login == None
            and (
                strtobool(query_params.get("parse_visas")[0])
                if query_params.get("parse_visas")
                else False
            )
        )
        if parse_visas and not config["ENABLE_VISA_UPDATE_CRON"]:
            # Note: this should not happen because the configuration is checked on app startup
            msg = "Trying to parse visas but `ENABLE_VISA_UPDATE_CRON` is disabled!"
            logger.error(msg)
            raise InternalError(msg)

        # do an on-the-fly usersync for this user to give them instant access after logging in through RAS
        # if GLOBAL_PARSE_VISAS_ON_LOGIN is true then we want to run it regardless of whether or not the client sent parse_visas on request
        if parse_visas:
            # get passport then call sync on it
            try:
                passport = (
                    flask.current_app.ras_client.get_encoded_passport_v11_userinfo(
                        userinfo
                    )
                )
            except Exception as e:
                err_msg = "Could not retrieve passport or visas"
                logger.error("{}: {}".format(e, err_msg))
                raise

            # now sync authz updates
            users_from_passports = fence.resources.ga4gh.passports.sync_gen3_users_authz_from_ga4gh_passports(
                [passport],
                pkey_cache=PKEY_CACHE,
                db_session=current_app.scoped_session(),
                skip_google_updates=True,
            )
            user_ids_from_passports = list(users_from_passports.keys())

            # TODO?
            # put_gen3_usernames_for_passport_into_cache(
            #     passport, usernames_from_current_passport
            # )

        # Store refresh token in db
        assert "refresh_token" in flask.g.tokens, "No refresh_token in user tokens"
        refresh_token = flask.g.tokens["refresh_token"]
        assert "id_token" in flask.g.tokens, "No id_token in user tokens"
        id_token = flask.g.tokens["id_token"]
        decoded_id = jwt.decode(
            id_token, algorithms=["RS256"], options={"verify_signature": False}
        )

        # Add 15 days to iat to calculate refresh token expiration time
        # TODO do they really not provide exp?
        issued_time = int(decoded_id.get("iat"))
        expires = config["RAS_REFRESH_EXPIRATION"]

        # User definied RAS refresh token expiration time
        if query_params.get("upstream_expires_in"):
            custom_refresh_expiration = query_params.get("upstream_expires_in")[0]
            expires = get_valid_expiration(
                custom_refresh_expiration,
                expires,
                expires,
            )

        flask.current_app.ras_client.store_refresh_token(
            user=user, refresh_token=refresh_token, expires=expires + issued_time
        )

        super(RASCallback, self).post_login(token_result=token_result)
