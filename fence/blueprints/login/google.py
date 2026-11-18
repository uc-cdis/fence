import flask

from fence.models import IdentityProvider
from fence.config import config
from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback
from fence.utils import append_query_params


class GoogleLogin(DefaultOAuth2Login):
    def __init__(self):
        super(GoogleLogin, self).__init__(
            idp_name=IdentityProvider.google, client=flask.current_app.google_client
        )


class GoogleCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(GoogleCallback, self).__init__(
            idp_name=IdentityProvider.google, client=flask.current_app.google_client
        )

    def get(self):
        # Check if this is a request to link account vs. actually log in
        if flask.session.get("google_link"):
            # `state` must survive this hop: the link callback checks it against
            # the value stored in the session when linking started
            forwarded_params = {
                param: flask.request.args[param]
                for param in ("code", "state")
                if param in flask.request.args
            }
            return flask.redirect(
                append_query_params(
                    config.get("BASE_URL", "") + "/link/google/callback",
                    **forwarded_params,
                )
            )

        return super(GoogleCallback, self).get()
