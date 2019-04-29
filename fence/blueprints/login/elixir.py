import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import UserError
from fence.models import IdentityProvider
from fence.config import config


class ElixirRedirect(Resource):
    def get(self):
        flask.redirect_url = flask.request.args.get("redirect")
        if flask.redirect_url:
            flask.session["redirect"] = flask.redirect_url

        if config.get("MOCK_ELIXIR_AUTH", False):
            email = flask.request.cookies.get(
                config.get("DEV_LOGIN_COOKIE_NAME"), "test@example.com"
            )
            return _login(email)

        return flask.redirect(flask.current_app.microsoft_client.get_auth_url())


class ElixirLogin(Resource):
    def get(self):
        code = flask.request.args.get("code")
        result = flask.current_app.microsoft_client.get_user_id(code)
        email = result.get("email")
        if email:
            return _login(email)
        raise UserError(result)


def _login(email):
    """
    Login user with given email from Elixir, then redirect if session has a saved
    redirect.
    """
    login_user(flask.request, email, IdentityProvider.elixir)
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify({"username": email})
