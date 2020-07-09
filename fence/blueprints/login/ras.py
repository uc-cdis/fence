import flask
import jwt
from flask_sqlalchemy_session import current_session

from fence.models import GA4GHVisaV1, IdentityProvider, User

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


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
