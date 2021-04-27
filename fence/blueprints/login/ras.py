import flask
import jwt
import os
from flask_sqlalchemy_session import current_session
import urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs

from fence.models import GA4GHVisaV1, IdentityProvider

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback

from fence.config import config
from fence.scripting.fence_create import init_syncer
from fence.utils import get_valid_expiration


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

    def post_login(self, user=None, token_result=None):
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

        encoded_visas = flask.g.userinfo.get("ga4gh_passport_v1", [])

        for encoded_visa in encoded_visas:
            # TODO: These visas must be validated!!!
            # i.e. (Remove `verify=False` in jwt.decode call)
            # But: need a routine for getting public keys per visa.
            # And we probably want to cache them.
            # Also needs any ga4gh-specific validation.
            # For now just read them without validation:
            decoded_visa = jwt.decode(encoded_visa, verify=False)

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

        usersync = config.get("USERSYNC", {})
        sync_from_visas = usersync.get("sync_from_visas", False)
        # Check if user has any project_access from a previous session or from usersync AND if fence is configured to use visas as authZ source
        # if not do an on-the-fly usersync for this user to give them instant access after logging in through RAS
        if not user.project_access and sync_from_visas:
            # Close previous db sessions. Leaving it open causes a race condition where we're viewing user.project_access while trying to update it in usersync
            # not closing leads to partially updated records
            current_session.close()
            DB = os.environ.get("FENCE_DB") or config.get("DB")
            if DB is None:
                try:
                    from fence.settings import DB
                except ImportError:
                    pass
            dbGaP = os.environ.get("dbGaP") or config.get("dbGaP")
            if not isinstance(dbGaP, list):
                dbGaP = [dbGaP]

            sync = init_syncer(
                dbGaP,
                None,
                DB,
            )
            sync.sync_single_user_visas(user, current_session)

        super(RASCallback, self).post_login()
