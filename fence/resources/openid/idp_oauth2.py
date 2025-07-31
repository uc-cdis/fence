from authlib.common.urls import add_params_to_uri
from authlib.integrations.requests_client import OAuth2Session
from cached_property import cached_property
import flask
from flask import current_app

from jose.exceptions import JWTError
import requests
import time
import datetime
import backoff
import jwt
from fence.utils import DEFAULT_BACKOFF_SETTINGS
from fence.errors import AuthError
from fence.models import UpstreamRefreshToken

from fence.jwt.validate import validate_jwt
from authutils.token.keys import get_public_key_for_token
from fence.config import config


class Oauth2ClientBase(object):
    """
    An generic oauth2 client class for interacting with an Identity Provider
    """

    def __init__(
        self,
        settings,
        logger,
        idp,
        scope=None,
        discovery_url=None,
        HTTP_PROXY=None,
        arborist=None,
    ):
        self.logger = logger
        self.settings = settings
        self.session = OAuth2Session(
            client_id=settings["client_id"],
            client_secret=settings["client_secret"],
            scope=scope or settings.get("scope") or "openid",
            redirect_uri=settings["redirect_url"],
        )

        self.discovery_url = (
            discovery_url
            or settings.get("discovery_url")
            or getattr(self, "DISCOVERY_URL", None)
            or ""
        )
        # display name for use in logs and error messages
        self.idp = idp
        self.HTTP_PROXY = HTTP_PROXY
        self.authz_groups_from_idp = []

        if not self.discovery_url and not settings.get("discovery"):
            self.logger.warning(
                f"OAuth2 Client for {self.idp} does not have a valid 'discovery_url'. "
                f"Some calls for this client may fail if they rely on the OIDC Discovery page. Use 'discovery' to configure clients without a discovery page."
            )

        self.read_authz_groups_from_tokens = self.settings.get(
            "is_authz_groups_sync_enabled", False
        )

        self.arborist = arborist

    @cached_property
    def discovery_doc(self):
        return requests.get(self.discovery_url)

    def get_proxies(self):
        if self.HTTP_PROXY and self.HTTP_PROXY.get("host"):
            url = "http://{}:{}".format(
                self.HTTP_PROXY["host"], str(self.HTTP_PROXY["port"])
            )
            return {"http": url}
        return None

    def get_token(self, token_endpoint, code):

        return self.session.fetch_token(
            url=token_endpoint, code=code, proxies=self.get_proxies()
        )

    def get_jwt_keys(self, jwks_uri):
        """
        Get jwt keys from provider's api
        Return None if there is an error while retrieving keys from the api
        """
        resp = requests.get(url=jwks_uri, proxies=self.get_proxies())

        if resp.status_code != requests.codes.ok:
            self.logger.error(
                "{} ERROR: Can not retrieve jwt keys from IdP's API {}".format(
                    resp.status_code, jwks_uri
                )
            )
            return None
        return resp.json()["keys"]

    def get_jwt_claims_identity(self, token_endpoint, jwks_endpoint, code):
        """
        Get jwt identity claims
        """

        token = self.get_token(token_endpoint, code)

        refresh_token = token.get("refresh_token", None)

        keys = self.get_jwt_keys(jwks_endpoint)

        # Extract issuer from the id token without signature verification
        try:
            decoded_id_token = jwt.decode(
                token["id_token"],
                options={"verify_signature": False},
                algorithms=["RS256"],
                key=keys,
            )
            issuer = decoded_id_token.get("iss")
        except JWTError as e:
            raise JWTError(f"Invalid token: {e}")

        # validate audience and hash. also ensure that the algorithm is correctly derived from the token.
        # hash verification has not been implemented yet
        verify_aud = self.settings.get("verify_aud", False)
        audience = self.settings.get("audience", self.settings.get("client_id"))

        decoded_access_token = None

        if self.read_authz_groups_from_tokens:
            try:
                decoded_access_token = validate_jwt(
                    encoded_token=token["access_token"],
                    aud=audience,
                    scope=None,
                    issuers=[issuer],
                    purpose=None,
                    require_purpose=False,
                    options={"verify_aud": verify_aud, "verify_hash": False},
                    attempt_refresh=True,
                )
            except JWTError as e:
                raise JWTError(f"Invalid token: {e}")

        return decoded_id_token, refresh_token, decoded_access_token

    def get_value_from_discovery_doc(self, key, default_value):
        """
        Given a key return a value by the recommended method of
        using their discovery url.
        """
        if self.discovery_url:
            self.logger.debug(f"Using {self.discovery_url} to get discovery doc")
            return_value = default_value
            if self.discovery_doc.status_code == requests.codes.ok:
                return_value = self.discovery_doc.json().get(key)
                if not return_value:
                    self.logger.warning(
                        "could not retrieve `{}` from {} response {}. "
                        "Defaulting to {}".format(
                            key, self.idp, self.discovery_doc.json(), default_value
                        )
                    )
                    return_value = default_value
                elif return_value != default_value and default_value != "":
                    self.logger.info(
                        "{}'s discovery doc {}, `{}`, differs from our "
                        "default, `{}`. Using {}'s...".format(
                            self.idp, key, return_value, default_value, self.idp
                        )
                    )
            else:
                # invalidate the cache
                del self.__dict__["discovery_doc"]

                self.logger.error(
                    "{} ERROR from {} API, could not retrieve `{}` from response {}. Defaulting to {}".format(
                        self.discovery_doc.status_code,
                        self.idp,
                        key,
                        self.discovery_doc.json(),
                        default_value,
                    )
                )
        # no `discovery_url`, try to use `discovery` config instead
        else:
            self.logger.debug(f"Using discovery from fence settings")
            return_value = self.settings.get("discovery", {}).get(key, default_value)

        if not return_value:
            discovery_data = (
                self.discovery_doc.json()
                if self.discovery_url
                else self.settings.get("discovery")
            )
            self.logger.error(
                "Could not retrieve `{}` from {} discovery doc {} "
                "and default value appears to not be set.".format(
                    key, self.idp, discovery_data
                )
            )

        return return_value

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", ""
        )
        uri, _ = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        if "idp" in flask.request.args:
            flask.session["upstream_idp"] = flask.request.args["idp"]

        # add query parameters to the url as configured in `authorization_url_param_map`
        params = {}
        for in_param, out_param in self.settings.get(
            "authorization_url_param_map", {}
        ).items():
            if in_param in flask.request.args:
                params[out_param] = flask.request.args[in_param]
        uri = add_params_to_uri(uri, params)

        return uri

    def get_auth_info(self, code):
        """
        Exchange code for tokens, get user_id from id token claims.
        Return dictionary with necessary field(s) for successfully logged in
        user OR "error" field with details of the error.
        """
        user_id_field = self.settings.get("user_id_field", "sub")

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            jwks_endpoint = self.get_value_from_discovery_doc("jwks_uri", "")
            claims, refresh_token, access_token = self.get_jwt_claims_identity(
                token_endpoint, jwks_endpoint, code
            )

            groups = None
            group_prefix = None

            organization_claim_field = self.settings.get(
                "organization_claim_field", "org"
            )
            firstname_claim_field = self.settings.get(
                "firstname_claim_field", "given_name"
            )
            lastname_claim_field = self.settings.get(
                "lastname_claim_field", "family_name"
            )
            email_claim_field = self.settings.get("email_claim_field", "email")

            if self.read_authz_groups_from_tokens:
                try:
                    group_claim_field = self.settings.get("group_claim_field", "groups")
                    # Get groups from access token
                    groups = access_token.get(group_claim_field)
                    group_prefix = self.settings.get("authz_groups_sync", {}).get(
                        "group_prefix", ""
                    )
                except KeyError as e:
                    self.logger.error(
                        f"Error: is_authz_groups_sync_enabled is enabled, however groups not found in claims: {e}"
                    )
                    raise Exception(e)

            if claims.get(user_id_field):
                if user_id_field == "email" and not claims.get("email_verified"):
                    return {"error": "Email is not verified"}
                return {
                    user_id_field: claims[user_id_field],
                    "mfa": self.has_mfa_claim(claims),
                    "refresh_token": refresh_token,
                    "iat": claims.get("iat"),
                    "exp": claims.get("exp"),
                    "groups": groups,
                    "group_prefix": group_prefix,
                    "org": claims.get(organization_claim_field),
                    "firstname": claims.get(firstname_claim_field),
                    "lastname": claims.get(lastname_claim_field),
                    "email": claims.get(email_claim_field),
                }
            else:
                self.logger.exception(
                    f"Can't get {user_id_field} from claims: {claims}"
                )
                return {"error": f"Can't get {user_id_field} from claims"}

        except Exception as e:
            self.logger.exception(f"Can't get user info from {self.idp}: {e}")
            return {"error": f"Can't get user info from {self.idp}: {e}"}

    def get_access_token(self, user, token_endpoint, db_session=None):
        """
        Get access_token using a refresh_token and store new refresh in upstream_refresh_token table.
        """
        refresh_token = None
        expires = None

        # Get the refresh_token and expiration from the database
        for row in sorted(user.upstream_refresh_tokens, key=lambda row: row.expires):
            refresh_token = row.refresh_token
            expires = row.expires

            # Check if the token is expired
            if time.time() > expires:
                # reset to check for next token
                refresh_token = None
                expires = None

                # delete expired refresh token
                db_session.delete(row)
                db_session.commit()

        if not refresh_token:
            raise AuthError("User doesn't have a valid, non-expired refresh token")

        verify_aud = self.settings.get("verify_aud", False)
        audience = self.settings.get("audience", self.settings.get("client_id"))

        refresh_kwargs = {
            "url": token_endpoint,
            "proxies": self.get_proxies(),
            "refresh_token": refresh_token,
        }

        if verify_aud:
            refresh_kwargs["audience"] = audience

        try:
            token_response = self.session.refresh_token(**refresh_kwargs)

            refresh_token = token_response["refresh_token"]
            # Fetching the expires at from token_response.
            # Defaulting to config settings.
            default_refresh_token_exp = self.settings.get(
                "default_refresh_token_exp", config["DEFAULT_REFRESH_TOKEN_EXP"]
            )
            expires_at = token_response.get(
                "expires_at", time.time() + default_refresh_token_exp
            )

            self.store_refresh_token(
                user,
                refresh_token=refresh_token,
                expires=expires_at,
                db_session=db_session,
            )

            return token_response
        except Exception as e:
            self.logger.exception(f"Error refreshing token for user {user.id}: {e}")
            raise AuthError("Failed to refresh access token.")

    def has_mfa_claim(self, decoded_id_token):
        """
        Determines if the claim denoting whether multifactor authentication was used is contained within the claims
        of the provided id_token.

        Parameters:
        - decoded_id_token (dict): The decoded id_token, a dict of claims -> claim values.

        """
        mfa_claim_info = self.settings.get("multifactor_auth_claim_info")
        if not mfa_claim_info:
            return False
        claim_name = mfa_claim_info.get("claim")
        mfa_values = mfa_claim_info.get("values")
        if not claim_name or not mfa_values:
            self.logger.warning(
                f"{self.idp} has a configured multifactor_auth_claim_info with a missing claim name "
                f"and values. Please check the OPENID_CONNECT settings for {self.idp} in the fence "
                f"config yaml."
            )
            return False
        mfa_claims = []
        if claim_name == "amr":
            mfa_claims = decoded_id_token.get(claim_name, [])
        elif claim_name == "acr":
            mfa_claims = decoded_id_token.get(claim_name, "").split(" ")
        else:
            self.logger.error(
                f"{claim_name} is neither AMR or ACR - cannot determine if MFA was used"
            )
            return False

        self.logger.info(
            f"Comparing token's {claim_name} claims: {mfa_claims} to mfa values {mfa_values}"
        )
        return len(set(mfa_claims) & set(mfa_values)) > 0

    def store_refresh_token(self, user, refresh_token, expires, db_session=None):
        """
        Store refresh token in db.
        """
        db_session = db_session or flask.current_app.scoped_session()
        user.upstream_refresh_tokens = []
        upstream_refresh_token = UpstreamRefreshToken(
            user=user,
            refresh_token=refresh_token,
            expires=expires,
        )
        current_db_session = db_session.object_session(upstream_refresh_token)
        current_db_session.add(upstream_refresh_token)
        db_session.commit()
        self.logger.info(
            f"Refresh token has been persisted for user: {user} , with expiration of {expires}"
        )

    def get_groups_from_token(self, decoded_access_token, group_prefix=""):
        """
        Retrieve and format groups from the decoded token based on a configurable field name.

        Args:
            decoded_access_token (dict): The decoded token containing claims.
            group_prefix (str): The prefix to strip from group names.

        Returns:
            list: A list of formatted group names.

        Variables:
            group_claim_field (str): The field name in the token that contains the group information.
            authz_groups_from_idp (list): The list of groups retrieved from the token, potentially empty.
        """
        # Retrieve the configured field name for groups, defaulting to 'groups'
        group_claim_field = self.settings.get("group_claim_field", "groups")
        authz_groups_from_idp = decoded_access_token.get(group_claim_field, [])

        if authz_groups_from_idp:
            authz_groups_from_idp = [
                group.removeprefix(group_prefix).lstrip("/")
                for group in authz_groups_from_idp
            ]
        return authz_groups_from_idp

    @backoff.on_exception(backoff.expo, Exception, **DEFAULT_BACKOFF_SETTINGS)
    def update_user_authorization(self, user, pkey_cache, db_session=None, **kwargs):
        """
        Update the user's authorization by refreshing their access token and synchronizing
        their group memberships with Arborist.

        This method refreshes the user's access token using an identity provider (IdP),
        retrieves and decodes the token, and optionally synchronizes the user's group
        memberships between the IdP and Arborist if the `groups` configuration is enabled.

        Args:
            user (User): The user object, which contains details like username and identity provider.
            pkey_cache (dict): A cache of public keys used for verifying JWT signatures.
            db_session (SQLAlchemy Session, optional): A database session object. If not provided,
                it defaults to the scoped session of the current application context.
            **kwargs: Additional keyword arguments.

        Raises:
            Exception: If there is an issue with retrieving the access token, decoding the token,
            or synchronizing the user's groups.

        Workflow:
        1. Retrieves the token endpoint and JWKS URI from the identity provider's discovery document.
        2. Uses the user's refresh token to get a new access token and persists it in the database.
        3. Decodes the ID token using the JWKS (JSON Web Key Set) retrieved from the IdP.
        4. If group synchronization is enabled:
           a. Retrieves the list of groups from Arborist.
           b. Retrieves the user's groups from the IdP.
           c. Adds the user to groups in Arborist that match the groups from the IdP.
           d. Removes the user from groups in Arborist that they are no longer part of in the IdP.

        Logging:
        - Logs the group membership synchronization activities (adding/removing users from groups).
        - Logs any issues encountered while refreshing the token or during group synchronization.

        Warnings:
        - If groups are not received from the IdP but group synchronization is enabled, logs a warning.

        """
        db_session = db_session or flask.current_app.scoped_session()

        expires_at = None

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")

            # this get_access_token also persists the refresh token in the db
            token = self.get_access_token(user, token_endpoint, db_session)

            verify_aud = self.settings.get("verify_aud", False)
            audience = self.settings.get("audience", self.settings.get("client_id"))

            key = get_public_key_for_token(
                token["id_token"], attempt_refresh=True, pkey_cache={}
            )

            decoded_access_token = jwt.decode(
                token["access_token"],
                key=key,
                options={"verify_aud": verify_aud, "verify_at_hash": False},
                algorithms=["RS256"],
                audience=audience,
            )
            self.logger.info("Token decoded and validated successfully.")

        except Exception as e:
            err_msg = "Could not refresh token"
            self.logger.exception("{}: {}".format(err_msg, e))
            raise

        if self.read_authz_groups_from_tokens:
            group_prefix = self.settings.get("authz_groups_sync", {}).get(
                "group_prefix", ""
            )

            # grab all groups defined in arborist
            arborist_groups = self.arborist.list_groups().get("groups")

            # groups defined in idp
            authz_groups_from_idp = self.get_groups_from_token(
                decoded_access_token, group_prefix
            )

            # if group name is in the list from arborist:
            if authz_groups_from_idp:
                authz_groups_from_idp = [
                    group.removeprefix(group_prefix).lstrip("/")
                    for group in authz_groups_from_idp
                ]

                idp_group_names = set(authz_groups_from_idp)

                # Expiration for group membership. Default 7 days
                group_membership_duration = self.settings.get(
                    "group_membership_expiration_duration", 3600 * 24 * 7
                )

                # Get the refresh token expiration from the token response
                refresh_token_expires_at = datetime.datetime.fromtimestamp(
                    token.get("expires_at", time.time()), tz=datetime.timezone.utc
                )

                # Calculate the configured group membership expiration
                configured_expires_at = datetime.datetime.now(
                    tz=datetime.timezone.utc
                ) + datetime.timedelta(seconds=group_membership_duration)

                # Ensure group membership does not exceed refresh token expiration
                group_membership_expires_at = min(
                    refresh_token_expires_at, configured_expires_at
                )

                # Add user to all matching groups from IDP
                for arborist_group in arborist_groups:
                    if arborist_group["name"] in idp_group_names:
                        self.logger.info(
                            f"Adding {user.username} to group: {arborist_group['name']}, sub: {user.id} exp: {group_membership_expires_at}"
                        )
                        self.arborist.add_user_to_group(
                            username=user.username,
                            group_name=arborist_group["name"],
                            expires_at=group_membership_expires_at,
                        )
            else:
                self.logger.warning(
                    f"is_authz_groups_sync_enabled feature is enabled, but did not receive groups from idp {self.idp} for user: {user.username}"
                )
