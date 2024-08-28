import flask
import jwt
import datetime

from cdislogging import get_logger
from flask_restful import Resource
from urllib.parse import urlparse, urlencode, parse_qsl

from sqlalchemy.sql.functions import grouping_sets

from fence.auth import login_user
from fence.blueprints.login.redirect import validate_redirect
from fence.config import config
from fence.errors import UserError
from fence.metrics import metrics

logger = get_logger(__name__)


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
        app=flask.current_app,
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
        self.is_mfa_enabled = "multifactor_auth_claim_info" in config[
            "OPENID_CONNECT"
        ].get(self.idp_name, {})
        self.app = app

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
        result = self.client.get_auth_info(code)

        refresh_token = result.get("refresh_token")

        username = result.get(self.username_field)
        if not username:
            raise UserError(
                f"OAuth2 callback error: no '{self.username_field}' in {result}"
            )

        email = result.get(self.email_field)
        id_from_idp = result.get(self.id_from_idp_field)

        resp = _login(username, self.idp_name, email=email, id_from_idp=id_from_idp)

        # # Store refresh token in db
        gen3_user = flask.g.user

        expires = result.get("exp")

        self.client.store_refresh_token(gen3_user,refresh_token,expires)

        # if self.client.config["check_groups"]
        #pass access token to post_login
        groups_from_idp = result.get("groups")
        self.post_login(
            user=flask.g.user,
            token_result=result,
            id_from_idp=id_from_idp,
            groups_from_idp=groups_from_idp,
            username=username,
            expires_at=expires
        )
        return resp

    def post_login(self, user=None, token_result=None, **kwargs):
        prepare_login_log(self.idp_name)
        metrics.add_login_event(
            user_sub=flask.g.user.id,
            idp=self.idp_name,
            fence_idp=flask.session.get("fence_idp"),
            shib_idp=flask.session.get("shib_idp"),
            client_id=flask.session.get("client_id"),
        )


        jwks_endpoint = self.client.get_value_from_discovery_doc("jwks_uri", "")
        keys = self.client.get_jwt_keys(jwks_endpoint)

        #if self.client.config["check_groups"]
        # grab all groups defined in arborist via self.app.arborist.list_groups()
        if self.client.read_group_information:
            arborist_groups = self.app.arborist.list_groups().get("groups")
            groups_from_idp = [group.removeprefix("group_prefix").lstrip('/') for group in kwargs.get("groups_from_idp") ]
            exp = datetime.datetime.fromtimestamp(
                kwargs.get("expires_at"),
                tz=datetime.timezone.utc
            )

            # split groups claim by " "
            # for group in groups:
            # groupname: remove this.client.config["prefix"] form the group
            # if groupname is in the list from arborist:
            # add user to group via: self.app.arborist.add_user_to_group() with the correct expires_at

            for idp_group in groups_from_idp:
                for arborist_group in arborist_groups:
                    if idp_group == arborist_group['name']:
                        self.app.arborist.add_user_to_group(
                            username=kwargs.get("username"),
                            group_name=idp_group,
                            expires_at=exp
                        )

        if token_result:
            username = token_result.get(self.username_field)
            if self.is_mfa_enabled:
                if token_result.get("mfa"):
                    logger.info(f"Adding mfa_policy for {username}")
                    self.app.arborist.grant_user_policy(
                        username=username,
                        policy_id="mfa_policy",
                    )
                    return
                else:
                    logger.info(f"Revoking mfa_policy for {username}")
                    self.app.arborist.revoke_user_policy(
                        username=username,
                        policy_id="mfa_policy",
                    )


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
