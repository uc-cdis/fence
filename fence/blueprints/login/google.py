import flask

from fence.models import IdentityProvider
from fence.config import config
from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


class GoogleLogin(DefaultOAuth2Login):
    def __init__(self):
        super(GoogleLogin, self).__init__(
            idp_name=IdentityProvider.google, client=flask.current_app.google_client
        )


class GoogleCallback(DefaultOAuth2Callback):
    from fence.metrics import google_login_counter

    def __init__(self):
        super(GoogleCallback, self).__init__(
            idp_name=IdentityProvider.google, client=flask.current_app.google_client
        )

    def get(self):
        # Check if this is a request to link account vs. actually log in
        if flask.session.get("google_link"):
            return flask.redirect(
                config.get("BASE_URL", "")
                + "/link/google/callback?code={}".format(flask.request.args.get("code"))
            )

        google_login_counter.inc()

        return super(GoogleCallback, self).get()
