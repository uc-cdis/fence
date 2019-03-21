import flask
from fence.config import config
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import UserError


class DefaultLogin(Resource):
    def __init__(self, idp_name, client, mock_username="test@example.com"):
        self.idp_name = idp_name
        self.client = client
        self.mock_username = mock_username

    def get(self):
        flask.redirect_url = flask.request.args.get("redirect")
        if flask.redirect_url:
            flask.session["redirect"] = flask.redirect_url

        config_name = "MOCK_{}_AUTH".format(self.idp_name.upper())

        if config.get(config_name, False):
            email = flask.request.cookies.get(
                config.get("DEV_LOGIN_COOKIE_NAME"), self.mock_username
            )
            return _login(email, self.idp_name)

        return flask.redirect(self.client.get_auth_url())


class DefaultCallback(Resource):
    def __init__(self, idp_name, client):
        self.idp_name = idp_name
        self.client = client

    def get(self):
        code = flask.request.args.get("code")
        result = self.client.get_user_id(code)
        email = result.get("email")
        if email:
            return _login(email, self.idp_name)
        raise UserError(result)


def _login(email, idp_name):
    """
    Login user with given email, then redirect if session has a saved
    redirect.
    """
    login_user(flask.request, email, idp_name)
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify({"username": email})
