import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.config import config
from fence.errors import UserError


class DefaultOAuth2Login(Resource):
    def __init__(self, idp_name, client, mock_username="test@example.com"):
        """
        Construct a resource for a login endpoint

        Args:
            idp_name (str): name for the identity provider
            client (fence.resources.openid.idp_oauth2.Oauth2ClientBase):
                Some instaniation of this base client class or a child class
            mock_username (str, optional): default fake username to use when
                configured to mock login and dev login cookie is not found
        """
        self.idp_name = idp_name
        self.client = client
        self.mock_username = mock_username

    def get(self):
        flask.redirect_url = flask.request.args.get("redirect")
        if flask.redirect_url:
            flask.session["redirect"] = flask.redirect_url

        config_name = "MOCK_{}_AUTH".format(self.idp_name.upper())

        if config.get(config_name, False):
            username = flask.request.cookies.get(
                config.get("DEV_LOGIN_COOKIE_NAME"), self.mock_username
            )
            return _login(username, self.idp_name)

        return flask.redirect(self.client.get_auth_url())


class DefaultOAuth2Callback(Resource):
    def __init__(self, idp_name, client, username_field="email"):
        """
        Construct a resource for a login callback endpoint

        Args:
            idp_name (str): name for the identity provider
            client (fence.resources.openid.idp_oauth2.Oauth2ClientBase):
                Some instaniation of this base client class or a child class
            username_field (str, optional): default field from response to
                retrieve the username
        """
        self.idp_name = idp_name
        self.client = client
        self.username_field = username_field

    def get(self):
        code = flask.request.args.get("code")
        result = self.client.get_user_id(code)
        username = result.get(self.username_field)
        if username:
            return _login(username, self.idp_name)
        raise UserError(result)


def _login(username, idp_name):
    """
    Login user with given username, then redirect if session has a saved
    redirect.
    """
    login_user(flask.request, username, idp_name)
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify({"username": username})
