import flask
from flask_restful import Resource
from urllib.parse import urlparse, urlencode, parse_qsl

from fence.auth import login_user
from fence.blueprints.login.redirect import validate_redirect
from fence.config import config
from fence.errors import UserError


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
            resp = _login(username, self.idp_name)
            prepare_login_log(self.idp_name)
            return resp

        return flask.redirect(self.client.get_auth_url())


class DefaultOAuth2Callback(Resource):
    def __init__(
        self,
        idp_name,
        client,
        username_field="email",
        email_field="email",
        id_from_idp_field="sub",
    ):
        """
        Construct a resource for a login callback endpoint

        Args:
            idp_name (str): name for the identity provider
            client (fence.resources.openid.idp_oauth2.Oauth2ClientBase):
                Some instaniation of this base client class or a child class
            username_field (str, optional): default field from response to
                retrieve the unique username
            email_field (str, optional): default field from response to
                retrieve the email (if available)
            id_from_idp_field (str, optional): default field from response to
                retrieve the idp-specific ID for this user (could be the same
                as username_field)
        """
        self.idp_name = idp_name
        self.client = client
        self.username_field = username_field
        self.email_field = email_field
        self.id_from_idp_field = id_from_idp_field

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
            redirect_uri = (
                dict(redirect_query_params).get("redirect_uri") or redirect_uri
            )  # the query params returns empty when we're using the default fence client

            final_query_params = urlencode(
                redirect_query_params + received_query_params
            )
            final_redirect_url = redirect_uri.split("?")[0] + "?" + final_query_params

            return flask.redirect(location=final_redirect_url)

        code = flask.request.args.get("code")
        result = self.client.get_user_id(code)
        username = result.get(self.username_field)
        if not username:
            raise UserError(
                f"OAuth2 callback error: no '{self.username_field}' in {result}"
            )

        email = result.get(self.email_field)
        id_from_idp = result.get(self.id_from_idp_field)

        resp = _login(username, self.idp_name, email=email, id_from_idp=id_from_idp)
        self.post_login(user=flask.g.user, token_result=result, id_from_idp=id_from_idp)
        return resp

    def post_login(self, user=None, token_result=None, **kwargs):
        prepare_login_log(self.idp_name)


def prepare_login_log(idp_name):
    flask.g.audit_data = {
        "username": flask.g.user.username,
        "sub": flask.g.user.id,
        "idp": idp_name,
        "fence_idp": flask.session.get("fence_idp"),
        "shib_idp": flask.session.get("shib_idp"),
        "client_id": flask.session.get("client_id"),
    }


def _login(username, idp_name, email=None, id_from_idp=None):
    """
    Login user with given username, then redirect if session has a saved
    redirect.
    """
    login_user(username, idp_name, email=email, id_from_idp=id_from_idp)

    if config["REGISTER_USERS_ON"]:
        if not flask.g.user.additional_info.get("registration_info"):
            return flask.redirect(
                config["BASE_URL"] + flask.url_for("register.register_user")
            )

    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify({"username": username})
