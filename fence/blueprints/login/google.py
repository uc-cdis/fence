import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.blueprints.login.redirect import RedirectMixin
from fence.errors import UserError
from fence.models import Client, IdentityProvider
from fence.config import config


class GoogleRedirect(RedirectMixin, Resource):
    def get(self):
        redirect_url = flask.request.args.get("redirect")
        client_id = flask.request.args.get("client")
        client = Client.get_by_client_id(client_id)
        self.validate_redirect(redirect_url, client)
        flask.redirect_url = redirect_url
        if flask.redirect_url:
            flask.session["redirect"] = flask.redirect_url

        if config.get("MOCK_GOOGLE_AUTH", False):
            return _login("test@example.com")

        return flask.redirect(flask.current_app.google_client.get_auth_url())


class GoogleLogin(Resource):
    def get(self):
        # Check if this is a request to link account vs. actually log in
        if flask.session.get("google_link"):
            return flask.redirect(
                config.get("BASE_URL", "")
                + "/link/google/callback?code={}".format(flask.request.args.get("code"))
            )
        code = flask.request.args.get("code")
        result = flask.current_app.google_client.get_user_id(code)
        email = result.get("email")
        if not email:
            raise UserError(result)
        return _login(email)


def _login(email):
    """
    Login user with given email from Google, then redirect if session has a saved
    redirect.
    """
    login_user(flask.request, email, IdentityProvider.google)
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify({"username": email})
