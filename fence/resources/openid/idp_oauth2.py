from authlib.integrations.requests_client import OAuth2Session
from cached_property import cached_property
from flask import current_app
from jose import jwt
import requests
import time

from fence.errors import AuthError
from fence.models import UpstreamRefreshToken


class Oauth2ClientBase(object):
    """
    An generic oauth2 client class for interacting with an Identity Provider
    """

    def __init__(
        self, settings, logger, idp, scope=None, discovery_url=None, HTTP_PROXY=None
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
        self.idp = idp  # display name for use in logs and error messages
        self.HTTP_PROXY = HTTP_PROXY

        if not self.discovery_url and not settings.get("discovery"):
            self.logger.warning(
                f"OAuth2 Client for {self.idp} does not have a valid 'discovery_url'. "
                f"Some calls for this client may fail if they rely on the OIDC Discovery page. Use 'discovery' to configure clients without a discovery page."
            )

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
        keys = self.get_jwt_keys(jwks_endpoint)

        return jwt.decode(
            token["id_token"],
            keys,
            options={"verify_aud": False, "verify_at_hash": False},
            algorithms=["RS256"],
        )

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
            claims = self.get_jwt_claims_identity(token_endpoint, jwks_endpoint, code)

            if claims.get(user_id_field):
                if user_id_field == "email" and not claims.get("email_verified"):
                    return {"error": "Email is not verified"}
                return {
                    user_id_field: claims[user_id_field],
                    "mfa": self.has_mfa_claim(claims),
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
