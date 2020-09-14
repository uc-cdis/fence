import flask
from flask_restful import Resource
from urllib.parse import urlparse, urlencode, parse_qsl, parse_qs

from fence.auth import login_user
from fence.blueprints.login.redirect import validate_redirect
from fence.config import config
from fence.errors import UserError
from fence.models import Client


class DefaultOAuth2Login(Resource):
    def __init__(self, idp_name, client):
        """
        Construct a resource for a login endpoint

        Args:
            idp_name (str): name for the identity provider
            client (fence.resources.openid.idp_oauth2.Oauth2ClientBase):
                Some instaniation of this base client class or a child class
        """
        self.idp_name = idp_name
        self.client = client

    def get(self):
        redirect_url = flask.request.args.get("redirect")
        validate_redirect(redirect_url)
        flask.redirect_url = redirect_url
        if flask.redirect_url:
            flask.session["redirect"] = flask.redirect_url

        mock_login = (
            config["OPENID_CONNECT"].get(self.idp_name.lower(), {}).get("mock", False)
        )

        # to support older cfgs, new cfgs should use the `mock` field in OPENID_CONNECT
        legacy_mock_login = config.get(
            "MOCK_{}_AUTH".format(self.idp_name.upper()), False
        )

        mock_default_user = (
            config["OPENID_CONNECT"]
            .get(self.idp_name.lower(), {})
            .get("mock_default_user", "test@example.com")
        )

        if mock_login or legacy_mock_login:
            # prefer dev cookie for mocked username, fallback on configuration
            username = flask.request.cookies.get(
                config.get("DEV_LOGIN_COOKIE_NAME"), mock_default_user
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
        # Check if user granted access
        if flask.request.args.get("error"):

            request_url = flask.request.url
            received_query_params = parse_qsl(
                urlparse(request_url).query, keep_blank_values=True
            )
            redirect_uri = flask.session.get("redirect") or config["BASE_URL"]
            redirect_query_params = parse_qsl(
                urlparse(redirect_uri).query, keep_blank_values=True
            )
            if "client_id" in redirect_query_params:
                redirect_query_dict = parse_qs(
                    urlparse(redirect_uri).query, keep_blank_values=True
                )
                client_id = redirect_query_dict["client_id"][0]
                with flask.current_app.db.session as session:
                    client = (
                        session.query(Client).filter_by(client_id=client_id).first()
                    )
                    redirect_uri = client.redirect_uri

            final_query_params = urlencode(
                redirect_query_params + received_query_params
            )
            final_redirect_url = redirect_uri.split("?")[0] + "?" + final_query_params

            return flask.redirect(location=final_redirect_url)

        code = flask.request.args.get("code")
        result = self.client.get_user_id(code)
        username = result.get(self.username_field)
        if username:
            resp = _login(username, self.idp_name)
            self.post_login(flask.g.user, result)
            return resp
        raise UserError(result)

    def post_login(self, user, token_result):
        pass


def _login(username, idp_name):
    """
    Login user with given username, then redirect if session has a saved
    redirect.
    """
    login_user(flask.request, username, idp_name)
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify({"username": username})
