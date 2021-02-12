import flask
import jwt
import os
from flask_sqlalchemy_session import current_session

from fence.models import GA4GHVisaV1, IdentityProvider, User

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback

from fence.config import config

from fence.sync.sync_users import UserSyncer


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

    def post_login(self, user, token_result):

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

        if not user.project_access:
            DB = os.environ.get("FENCE_DB") or config.get("DB")
            if DB is None:
                try:
                    from fence.settings import DB
                except ImportError:
                    pass
            dbGaP = os.environ.get("dbGaP") or config.get("dbGaP")
            if not isinstance(dbGaP, list):
                dbGaP = [dbGaP]

            sync = UserSyncer(
                dbGaP=dbGaP,
                DB=DB,
                project_mapping=None,
                db_session=current_session,
                single_visa_sync=True,
            )
            sync.sync_single_user_visas(user, current_session)
        # Store refresh token in db
        refresh_token = flask.g.tokens.get("refresh_token")
        id_token = flask.g.tokens.get("id_token")
        decoded_id = jwt.decode(id_token, verify=False)
        # Add 15 days to iat to calculate refresh token expiration time
        expires = int(decoded_id.get("iat")) + config["RAS_REFRESH_EXPIRATION"]
        flask.current_app.ras_client.store_refresh_token(
            user=user, refresh_token=refresh_token, expires=expires
        )
