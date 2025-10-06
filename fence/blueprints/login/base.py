import time
import base64
import json
from urllib.parse import urlparse, urlencode, parse_qsl
import jwt

from flask import current_app
import flask
from cdislogging import get_logger
from flask_restful import Resource

from fence.auth import login_user_or_require_registration, get_ip_information_string
from fence.blueprints.login.redirect import validate_redirect
from fence.blueprints.register import add_user_registration_info_to_database
from fence.config import config
from fence.errors import UserError, Unauthorized
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

        # `post_registration_redirect`: After registering, the user is sent back to this endpoint
        # to complete the login flow.
        # Reconstruct and store the current URL - we can't just use `request.url` here because
        # it's missing the `/user` prefix. This is caused by the revproxy stripping the URL
        # prefix before forwarding requests to Fence.
        current_url = config["BASE_URL"] + flask.request.path
        if flask.request.query_string:
            current_url += f"?{flask.request.query_string.decode('utf-8')}"
        flask.session["post_registration_redirect"] = current_url

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
            # log in the mocked user
            resp, _ = _login_and_register(username, self.idp_name)
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

        # Config option to explicitly persist refresh tokens
        self.persist_refresh_token = False

        self.read_authz_groups_from_tokens = False

        self.app = app

        self.persist_refresh_token = (
            config["OPENID_CONNECT"].get(self.idp_name, {}).get("persist_refresh_token")
        )

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

        resp, user_is_logged_in = _login_and_register(
            username,
            self.idp_name,
            email=email,
            id_from_idp=id_from_idp,
            token_result=result,
        )

        if not user_is_logged_in:
            return resp

        if not hasattr(flask.g, "user") or not flask.g.user:
            raise UserError("Authentication failed: flask.g.user is missing.")

        expires = self.extract_exp(refresh_token)

        # if the access token is not a JWT, or does not carry exp,
        # default to now + REFRESH_TOKEN_EXPIRES_IN
        if expires is None:
            expires = int(time.time()) + config["REFRESH_TOKEN_EXPIRES_IN"]
            logger.info(f"Refresh token not in JWT, using default: {expires}")

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
        2. Manually base64 decoding the token's payload (if it's a JWT).

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

        # Method 2: Manual base64 decoding
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
            logger.info(f"Method 2 (Manual decoding) failed: {e}")

        # If all methods fail, return None
        return None

    def post_login(self, user=None, token_result=None, **kwargs):
        prepare_login_log(self.idp_name)

        metrics.add_login_event(
            user_sub=flask.g.user.id,
            idp=self.idp_name,
            upstream_idp=flask.session.get("upstream_idp"),
            shib_idp=flask.session.get("shib_idp"),
            client_id=flask.session.get("client_id"),
        )

        if self.read_authz_groups_from_tokens:
            self.client.update_user_authorization(
                user=user, pkey_cache=None, db_session=None, idp_name=self.idp_name
            )

        if token_result:
            username = token_result.get(self.username_field)
            if self.app.arborist and self.is_mfa_enabled:
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
    x_forwarded_headers = [
        f"{header}:{value}" for header, value in flask.request.headers if "X-" in header
    ]
    flask.g.audit_data = {
        "username": flask.g.user.username,
        "sub": flask.g.user.id,
        "idp": idp_name,
        "upstream_idp": flask.session.get("upstream_idp"),
        "shib_idp": flask.session.get("shib_idp"),
        "client_id": flask.session.get("client_id"),
        "additional_data": x_forwarded_headers,
        "ip": get_ip_information_string(),
    }


def _login_and_register(
    username,
    idp_name,
    email=None,
    id_from_idp=None,
    token_result=None,
    upstream_idp=None,
    shib_idp=None,
):
    """
    Login user with given username, then automatically register if needed,
    and finally redirect if session has a saved redirect.

    Return:
        bool: whether the user has been logged in (if registration is enabled and the user is not
            registered, this would be False)
    """
    user_is_logged_in = login_user_or_require_registration(
        username,
        idp_name,
        upstream_idp=upstream_idp,
        shib_idp=shib_idp,
        email=email,
        id_from_idp=id_from_idp,
    )

    auto_registration_enabled = (
        config["OPENID_CONNECT"]
        .get(idp_name, {})
        .get("enable_idp_users_registration", False)
    )

    if config["REGISTER_USERS_ON"]:
        user = flask.g.user
        if not user.additional_info.get("registration_info"):
            # If enabled, automatically register user from IdP
            if auto_registration_enabled:
                organization_claim_field = (
                    config["OPENID_CONNECT"]
                    .get(idp_name, {})
                    .get("organization_claim_field", "org")
                )
                firstname_claim_field = (
                    config["OPENID_CONNECT"]
                    .get(idp_name, {})
                    .get("firstname_claim_field", "firstname")
                )
                lastname_claim_field = (
                    config["OPENID_CONNECT"]
                    .get(idp_name, {})
                    .get("lastname_claim_field", "lastname")
                )
                email_claim_field = (
                    config["OPENID_CONNECT"]
                    .get(idp_name, {})
                    .get("email_claim_field", "email")
                )
                firstname = token_result.get(firstname_claim_field)
                lastname = token_result.get(lastname_claim_field)
                organization = token_result.get(organization_claim_field)
                email = token_result.get(email_claim_field)
                if email is None:
                    raise UserError("OAuth2 id token is missing email claim")
                # Log warnings and set defaults if needed
                if not firstname or not lastname:
                    logger.warning(
                        f"User {username} missing name fields. Proceeding with minimal info."
                    )
                    firstname = firstname or "Unknown"
                    lastname = lastname or "Unknown"
                if not organization:
                    logger.info(
                        f"User {username} missing organization. Defaulting to None."
                    )
                add_user_registration_info_to_database(
                    user, firstname, lastname, organization, email
                )
            else:
                return (
                    flask.redirect(
                        config["BASE_URL"] + flask.url_for("register.register_user")
                    ),
                    user_is_logged_in,
                )

    if flask.session.get("redirect"):
        return flask.redirect(flask.session["redirect"]), user_is_logged_in

    return flask.jsonify({"username": username}), user_is_logged_in
