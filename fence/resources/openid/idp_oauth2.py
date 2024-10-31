from authlib.integrations.requests_client import OAuth2Session
from boto3 import client
from cached_property import cached_property
from flask import current_app
from jose import jwt
from jose.exceptions import JWTError, JWTClaimsError
import requests
import time
import datetime
import backoff
from fence.utils import DEFAULT_BACKOFF_SETTINGS
from fence.errors import AuthError
from fence.models import UpstreamRefreshToken


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
        self.groups_from_idp = []
        self.client_id = self.settings.get("client_id", "")
        self.client_secret = self.settings.get("client_secret", "")

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

    def get_raw_token_claims(self, token_id):
        """Extracts unvalidated claims from a JWT (JSON Web Token).

        This function decodes a JWT and extracts claims without verifying
        the token's signature or audience. It is intended for cases where
        access to the raw, unvalidated token claims is sufficient.

        Args:
            token_id (str): The JWT token from which to extract claims.

        Returns:
            dict: A dictionary of token claims if decoding is successful.

        Raises:
            JWTError: If there is an error decoding the token without validation.

        Notes:
            This function does not perform any validation of the token. It should
            only be used in contexts where validation is not critical or is handled
            elsewhere in the application.
        """
        try:
            # Decode without verification
            unvalidated_claims = jwt.decode(
                token_id, options={"verify_signature": False}
            )
            self.logger.info("Raw token claims extracted successfully.")
            return unvalidated_claims
        except JWTError as e:
            self.logger.error(f"Error extracting claims: {e}")
            raise JWTError("Unable to decode the token without validation.")

    def decode_and_validate_token(self, token_id, keys, audience, verify_aud=True):
        """Decodes and validates a JWT (JSON Web Token) using provided keys and audience.

        This function decodes a JWT and validates its signature and audience claim,
        if required. It is typically used for tokens that require validation to
        ensure integrity and authenticity.

        Args:
            token_id (str): The JWT token to decode.
            keys (list): A list of keys to use for decoding the token, usually
                provided by the Identity Provider (IdP).
            audience (str): The expected audience (`aud`) claim to verify within the token.
            verify_aud (bool, optional): Flag to enable or disable audience verification.
                Defaults to True.

        Returns:
            dict: A dictionary of validated token claims if decoding and validation are successful.

        Raises:
            JWTClaimsError: If the token's claims, such as audience, do not match the expected values.
            JWTError: If there is an error with the JWT structure or verification.

        Notes:
            - This function assumes the token is signed using the RS256 algorithm.
            - Audience verification (`aud`) is performed if `verify_aud` is set to True.
        """
        try:
            validated_claims = jwt.decode(
                token_id,
                keys,
                options={"verify_aud": verify_aud, "verify_at_hash": False},
                algorithms=["RS256"],
                audience=audience,
            )
            self.logger.info("Token decoded and validated successfully.")
            return validated_claims
        except JWTClaimsError as e:
            self.logger.error(f"Claim error: {e}")
            raise JWTClaimsError(f"Invalid audience: {e}")
        except JWTError as e:
            self.logger.error(f"JWT error: {e}")
            raise JWTError(f"JWT error occurred: {e}")

    def get_jwt_claims_identity(self, token_endpoint, jwks_endpoint, code):
        """
        Get jwt identity claims
        """

        token = self.get_token(token_endpoint, code)

        keys = self.get_jwt_keys(jwks_endpoint)

        refresh_token = token.get("refresh_token", None)

        # validate audience and hash. also ensure that the algorithm is correctly derived from the token.
        # hash verification has not been implemented yet
        verify_aud = self.settings.get("verify_aud", False)
        audience = self.settings.get("audience", self.settings.get("client_id"))
        return (
            self.decode_and_validate_token(
                token["id_token"], keys, audience, verify_aud
            ),
            refresh_token,
        )

    def get_value_from_discovery_doc(self, key, default_value):
        """
        Given a key return a value by the recommended method of
        using their discovery url.
        """
        if self.discovery_url:
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
            claims, refresh_token = self.get_jwt_claims_identity(
                token_endpoint, jwks_endpoint, code
            )

            groups = None
            group_prefix = None

            if self.read_authz_groups_from_tokens:
                try:
                    groups = claims.get("groups")
                    group_prefix = self.settings.get("authz_groups_sync", {}).get(
                        "group_prefix", ""
                    )
                except (AttributeError, TypeError) as e:
                    self.logger.error(
                        f"Error: is_authz_groups_sync_enabled is enabled, required values not configured: {e}"
                    )
                    raise Exception(e)
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
                }
            else:
                self.logger.exception(
                    f"Can't get {user_id_field} from claims: {claims}"
                )
                return {"error": f"Can't get {user_id_field} from claims"}

        except Exception as e:
            self.logger.exception(f"Can't get user info from {self.idp}: {e}")
            return {"error": f"Can't get user info from {self.idp}"}

    def get_access_token(self, user, token_endpoint, db_session=None):
        """
        Get access_token using a refresh_token and store new refresh in upstream_refresh_token table.
        """
        # this function is not correct. use self.session.fetch_access_token,
        # validate the token for audience and then return the validated token.
        # Still store the refresh token. it will be needed for periodic re-fetching of information.
        refresh_token = None
        expires = None
        # get refresh_token and expiration from db
        for row in sorted(user.upstream_refresh_tokens, key=lambda row: row.expires):
            refresh_token = row.refresh_token
            expires = row.expires
            if time.time() > expires:
                # reset to check for next token
                refresh_token = None
                expires = None

                # delete expired refresh token
                db_session.delete(row)
                db_session.commit()

        if not refresh_token:
            raise AuthError("User doesn't have a valid, non-expired refresh token")

        token_response = self.session.refresh_token(
            url=token_endpoint,
            proxies=self.get_proxies(),
            refresh_token=refresh_token,
        )
        refresh_token = token_response["refresh_token"]

        self.store_refresh_token(
            user,
            refresh_token=refresh_token,
            expires=expires,
            db_session=db_session,
        )

        return token_response

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
        db_session = db_session or current_app.scoped_session()
        user.upstream_refresh_tokens = []
        upstream_refresh_token = UpstreamRefreshToken(
            user=user,
            refresh_token=refresh_token,
            expires=expires,
        )
        current_db_session = db_session.object_session(upstream_refresh_token)
        current_db_session.add(upstream_refresh_token)
        db_session.commit()

    def get_groups_from_token(self, decoded_token_id, group_prefix=""):
        """Retrieve and format groups from the decoded token."""
        groups_from_idp = decoded_token_id.get("groups", [])
        if groups_from_idp:
            groups_from_idp = [
                group.removeprefix(group_prefix).lstrip("/")
                for group in groups_from_idp
            ]
        return groups_from_idp

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
        db_session = db_session or current_app.scoped_session()

        # Initialize the failure flag for group removal
        removal_failed = False

        expires_at = None

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")

            # this get_access_token also persists the refresh token in the db
            token = self.get_access_token(user, token_endpoint, db_session)
            jwks_endpoint = self.get_value_from_discovery_doc("jwks_uri", "")
            keys = self.get_jwt_keys(jwks_endpoint)
            expires_at = token["expires_at"]
            verify_aud = self.settings.get("verify_aud", False)
            audience = self.settings.get("audience", self.settings.get("client_id"))
            decoded_token_id = self.decode_and_validate_token(
                token_id=token["id_token"],
                keys=keys,
                audience=audience,
                verify_aud=verify_aud,
            )

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
            groups_from_idp = self.get_groups_from_token(decoded_token_id, group_prefix)

            exp = datetime.datetime.fromtimestamp(expires_at, tz=datetime.timezone.utc)

            # if group name is in the list from arborist:
            if groups_from_idp:
                groups_from_idp = [
                    group.removeprefix(group_prefix).lstrip("/")
                    for group in groups_from_idp
                ]

                idp_group_names = set(groups_from_idp)

                # Add user to all matching groups from IDP
                for arborist_group in arborist_groups:
                    if arborist_group["name"] in idp_group_names:
                        self.logger.info(
                            f"Adding {user.username} to group: {arborist_group['name']}, sub: {user.id} exp: {exp}"
                        )
                        self.arborist.add_user_to_group(
                            username=user.username,
                            group_name=arborist_group["name"],
                            expires_at=exp,
                        )

                # Remove user from groups in Arborist that they are not part of in IDP
                for arborist_group in arborist_groups:
                    if arborist_group["name"] not in idp_group_names:
                        if user.username in arborist_group.get("users", []):
                            try:
                                self.remove_user_from_arborist_group(
                                    user.username, arborist_group["name"]
                                )
                            except Exception as e:
                                self.logger.error(
                                    f"Failed to remove {user.username} from group {arborist_group['name']}: {e}"
                                )
                                removal_failed = (
                                    # Set the failure flag if any removal fails
                                    True
                                )

            else:
                self.logger.warning(
                    f"is_authz_groups_sync_enabled feature is enabled, but did not receive groups from idp {self.idp} for user: {user.username}"
                )

        # Raise an exception if any group removal failed
        if removal_failed:
            raise Exception("One or more group removals failed.")

    def remove_user_from_arborist_group(self, username, group_name):
        """
        Attempt to remove a user from an Arborist group, catching any errors to allow
        processing of remaining groups. Logs errors and re-raises them after all removals are attempted.
        """
        self.logger.info(f"Removing {username} from group: {group_name}")
        self.arborist.remove_user_from_group(username=username, group_name=group_name)
