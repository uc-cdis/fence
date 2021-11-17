import flask
import jwt
import os

# the whole fence_create module is imported to avoid issue with circular imports
import fence.scripting.fence_create
from distutils.util import strtobool
from urllib.parse import urlparse, parse_qs

from authutils.errors import JWTError
from cdislogging import get_logger
from flask_sqlalchemy_session import current_session
from gen3authz.client.arborist.client import ArboristClient

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback
from fence.config import config
from fence.jwt.validate import validate_jwt
from fence.models import GA4GHVisaV1, IdentityProvider
from fence.utils import get_valid_expiration

logger = get_logger(__name__)


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
        # TODO: I'm not convinced this code should be in post_login.
        # Just putting it in here for now, but might refactor later.
        # This saves us a call to RAS /userinfo, but will not make sense
        # when there is more than one visa issuer.

        # Clear all of user's visas, to avoid having duplicate visas
        # where only iss/exp/jti differ
        # TODO: This is not IdP-specific and will need a rethink when
        # we have multiple IdPs
        user.ga4gh_visas_v1 = []

        current_session.commit()

        userinfo = flask.g.userinfo

        encoded_visas = []

        try:
            encoded_visas = flask.current_app.ras_client.get_encoded_visas_v11_userinfo(
                userinfo
            )
        except Exception as e:
            err_msg = "Could not retrieve visas"
            logger.error("{}: {}".format(e, err_msg))
            raise

        for encoded_visa in encoded_visas:
            try:
                # Validate the visa per GA4GH AAI "Embedded access token" format rules.
                # pyjwt also validates signature and expiration.
                decoded_visa = validate_jwt(
                    encoded_token=encoded_visa,
                    # Embedded token must contain scope claim, which must include openid
                    scope={"openid", "ga4gh_passport_v1"},
                    issuers=config["GA4GH_VISA_ISSUER_ALLOWLIST"],
                    require_purpose=False,
                    # Embedded token must contain iss, sub, iat, exp claims
                    # options={"require": ["iss", "sub", "iat", "exp"]},
                    # ^ FIXME 2021-05-13: Above needs pyjwt>=v2.0.0, which requires cryptography>=3.
                    # Once we can unpin and upgrade cryptography and pyjwt, switch to above "options" arg.
                    # For now, pyjwt 1.7.1 is able to require iat and exp;
                    # authutils' validate_jwt (i.e. the function being called) checks issuers already (see above);
                    # and we will check separately for sub below.
                    options={
                        "require_iat": True,
                        "require_exp": True,
                        "verify_aud": False,
                    },
                )

                # Also require 'sub' claim (see note above about pyjwt and the options arg).
                if "sub" not in decoded_visa:
                    raise JWTError("Visa is missing the 'sub' claim.")
                # Embedded token must not contain aud claim
                if "aud" in decoded_visa:
                    raise JWTError("Visa contains the 'aud' claim.")
            except Exception as e:
                logger.error("Visa failed validation: {}. Discarding visa.".format(e))
                continue

            visa = GA4GHVisaV1(
                user=user,
                source=decoded_visa["ga4gh_visa_v1"]["source"],
                type=decoded_visa["ga4gh_visa_v1"]["type"],
                asserted=int(decoded_visa["ga4gh_visa_v1"]["asserted"]),
                expires=int(decoded_visa["exp"]),
                ga4gh_visa=encoded_visa,
            )
            current_session.add(visa)
            current_session.commit()

        # Store refresh token in db
        assert "refresh_token" in flask.g.tokens, "No refresh_token in user tokens"
        refresh_token = flask.g.tokens["refresh_token"]
        assert "id_token" in flask.g.tokens, "No id_token in user tokens"
        id_token = flask.g.tokens["id_token"]
        decoded_id = jwt.decode(id_token, verify=False)

        # Add 15 days to iat to calculate refresh token expiration time
        issued_time = int(decoded_id.get("iat"))
        expires = config["RAS_REFRESH_EXPIRATION"]

        # User definied RAS refresh token expiration time
        parsed_url = urlparse(flask.session.get("redirect"))
        query_params = parse_qs(parsed_url.query)
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

        global_parse_visas_on_login = config["GLOBAL_PARSE_VISAS_ON_LOGIN"]
        usersync = config.get("USERSYNC", {})
        sync_from_visas = usersync.get("sync_from_visas", False)
        parse_visas = global_parse_visas_on_login or (
            global_parse_visas_on_login == None
            and (
                strtobool(query_params.get("parse_visas")[0])
                if query_params.get("parse_visas")
                else False
            )
        )
        # if sync_from_visas and (global_parse_visas_on_login or global_parse_visas_on_login == None):
        # Check if user has any project_access from a previous session or from usersync AND if fence is configured to use visas as authZ source
        # if not do an on-the-fly usersync for this user to give them instant access after logging in through RAS
        # If GLOBAL_PARSE_VISAS_ON_LOGIN is true then we want to run it regardless of whether or not the client sent parse_visas on request
        if sync_from_visas and parse_visas and not user.project_access:
            # Close previous db sessions. Leaving it open causes a race condition where we're viewing user.project_access while trying to update it in usersync
            # not closing leads to partially updated records
            current_session.close()

            DB = os.environ.get("FENCE_DB") or config.get("DB")
            if DB is None:
                try:
                    from fence.settings import DB
                except ImportError:
                    pass

            arborist = ArboristClient(
                arborist_base_url=config["ARBORIST"],
                logger=get_logger("user_syncer.arborist_client"),
                authz_provider="user-sync",
            )
            dbGaP = os.environ.get("dbGaP") or config.get("dbGaP")
            if not isinstance(dbGaP, list):
                dbGaP = [dbGaP]

            sync = fence.scripting.fence_create.init_syncer(
                dbGaP,
                None,
                DB,
                arborist=arborist,
            )
            sync.sync_single_user_visas(user, user.ga4gh_visas_v1, current_session)

        super(RASCallback, self).post_login(id_from_idp=id_from_idp)
