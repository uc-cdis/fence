import time
import base64
import json
from urllib.parse import urlparse, urlencode, parse_qsl
import jwt
import requests
import flask
from cdislogging import get_logger
from flask_restful import Resource
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
                Some instantiation of this base client class or a child class
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
        app=None,
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

        # Config option to explicitly persist refresh tokens
        self.persist_refresh_token = False

        self.read_authz_groups_from_tokens = False

        self.app = app

        # This block of code probably need to be made more concise
        if "persist_refresh_token" in config["OPENID_CONNECT"].get(self.idp_name, {}):
            self.persist_refresh_token = config["OPENID_CONNECT"][self.idp_name][
                "persist_refresh_token"
            ]

        if "is_authz_groups_sync_enabled" in config["OPENID_CONNECT"].get(
            self.idp_name, {}
        ):
            self.read_authz_groups_from_tokens = config["OPENID_CONNECT"][
                self.idp_name
            ]["is_authz_groups_sync_enabled"]

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

        expires = self.extract_exp(refresh_token)

        # if the access token is not a JWT, or does not carry exp,
        # default to now + REFRESH_TOKEN_EXPIRES_IN
        if expires is None:
            expires = int(time.time()) + config["REFRESH_TOKEN_EXPIRES_IN"]

        # Store refresh token in db
        should_persist_token = (
            self.persist_refresh_token or self.read_authz_groups_from_tokens
        )
        if should_persist_token:
            # Ensure flask.g.user exists to avoid a potential AttributeError
            if getattr(flask.g, "user", None):
                self.client.store_refresh_token(flask.g.user, refresh_token, expires)
            else:
                logger.error(
                    "User information is missing from flask.g; cannot store refresh token."
                )

        self.post_login(
            user=flask.g.user,
            token_result=result,
            id_from_idp=id_from_idp,
        )

        return resp

    def extract_exp(self, refresh_token):
        """
        Extract the expiration time (`exp`) from a refresh token.

        This function attempts to retrieve the expiration time from the provided
        refresh token using three methods:

        1. Using PyJWT to decode the token (without signature verification).
        2. Introspecting the token (if supported by the identity provider).
        3. Manually base64 decoding the token's payload (if it's a JWT).

        **Disclaimer:** This function assumes that the refresh token is valid and
        does not perform any JWT validation. For JWTs from an OpenID Connect (OIDC)
        provider, validation should be done using the public keys provided by the
        identity provider (from the JWKS endpoint) before using this function to
        extract the expiration time. Without validation, the token's integrity and
        authenticity cannot be guaranteed, which may expose your system to security
        risks. Ensure validation is handled prior to calling this function,
        especially in any public or production-facing contexts.

        Args:
            refresh_token (str): The JWT refresh token from which to extract the expiration.

        Returns:
            int or None: The expiration time (`exp`) in seconds since the epoch,
            or None if extraction fails.
        """

        # Method 1: PyJWT
        try:
            # Skipping keys since we're not verifying the signature
            decoded_refresh_token = jwt.decode(
                refresh_token,
                options={
                    "verify_aud": False,
                    "verify_at_hash": False,
                    "verify_signature": False,
                },
                algorithms=["RS256", "HS512"],
            )
            exp = decoded_refresh_token.get("exp")

            if exp is not None:
                return exp
        except Exception as e:
            logger.info(f"Refresh token expiry: Method (PyJWT) failed: {e}")

        # Method 2: Introspection
        try:
            introspection_response = self.introspect_token(refresh_token)
            exp = introspection_response.get("exp")

            if exp is not None:
                return exp
        except Exception as e:
            logger.info(f"Refresh token expiry: Method Introspection failed: {e}")

        # Method 3: Manual base64 decoding
        try:
            # Assuming the token is a JWT (header.payload.signature)
            payload_encoded = refresh_token.split(".")[1]
            # Add necessary padding for base64 decoding
            payload_encoded += "=" * (4 - len(payload_encoded) % 4)
            payload_decoded = base64.urlsafe_b64decode(payload_encoded)
            payload_json = json.loads(payload_decoded)
            exp = payload_json.get("exp")

            if exp is not None:
                return exp
        except Exception as e:
            logger.info(f"Method 3 (Manual decoding) failed: {e}")

        # If all methods fail, return None
        return None

    def introspect_token(self, token):

        try:
            introspect_endpoint = self.client.get_value_from_discovery_doc(
                "introspection_endpoint", ""
            )

            # Headers and payload for the introspection request
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {
                "token": token,
                "client_id": self.client.client_id,
                "client_secret": self.client.client_secret,
            }

            response = requests.post(introspect_endpoint, headers=headers, data=data)

            if response.status_code == 200:
                return response.json()
            else:
                logger.info(f"Error introspecting token: {response.status_code}")
                return None

        except Exception as e:
            logger.info(f"Error introspecting token: {e}")
            return None

    def post_login(self, user=None, token_result=None, **kwargs):
        prepare_login_log(self.idp_name)

        metrics.add_login_event(
            user_sub=flask.g.user.id,
            idp=self.idp_name,
            fence_idp=flask.session.get("fence_idp"),
            shib_idp=flask.session.get("shib_idp"),
            client_id=flask.session.get("client_id"),
        )

        # this attribute is only applicable to some OAuth clients
        # (e.g., not all clients need is_read_authz_groups_from_tokens_enabled)
        if self.read_authz_groups_from_tokens:
            self.client.update_user_authorization(
                user=user, pkey_cache=None, db_session=None, idp_name=self.idp_name
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
