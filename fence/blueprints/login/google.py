import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import UserError
from fence.models import IdentityProvider
from fence.config import config


class GoogleRedirect(Resource):
    def get(self):
        flask.redirect_url = flask.request.args.get("redirect")
        if flask.redirect_url:
            flask.session["redirect"] = flask.redirect_url

        if config.get("MOCK_GOOGLE_AUTH", False):
            email = flask.request.cookies.get(
                config.get("DEV_LOGIN_COOKIE_NAME"), "test@example.com"
            )
            return _login(email)

        return flask.redirect(flask.current_app.google_client.get_auth_url())


class GoogleLogin(Resource):
    def get(self):
        # Check if this is a request to link account vs. actually log in
        if flask.session.get("google_link"):
            return flask.redirect(
                config.get("BASE_URL", "")
                + "/link/google/callback?code={}".format(flask.request.args.get("code"))
            )
        else:
            code = flask.request.args.get("code")
            result = flask.current_app.google_client.get_user_id(code)
            email = result.get("email")
            if email:
                return _login(email)
            raise UserError(result)


def _login(email):
    """
    Login user with given email from Google, then redirect if session has a saved
    redirect.
    """
    login_user(flask.request, email, IdentityProvider.google)
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify({"username": email})
