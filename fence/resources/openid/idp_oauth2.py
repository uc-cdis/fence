from authlib.client import OAuth2Session
from cached_property import cached_property
from flask_sqlalchemy_session import current_session
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

    def get_user_id(self, code):
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
                return {user_id_field: claims[user_id_field]}
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
        Get access_token using a refresh_token and store it in upstream_refresh_token table.
        """
        refresh_token = None
        expires = None

        # get refresh_token and expiration from db
        for row in user.upstream_refresh_tokens:
            refresh_token = row.refresh_token
            expires = row.expires

        if not refresh_token:
            raise AuthError("User doesnt have a refresh token")
        if time.time() > expires:
            raise AuthError("Refresh token expired. Please login again.")

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

    def store_refresh_token(
        self, user, refresh_token, expires, db_session=current_session
    ):
        """
        Store refresh token in db.
        """
        user.upstream_refresh_tokens = []
        upstream_refresh_token = UpstreamRefreshToken(
            user=user,
            refresh_token=refresh_token,
            expires=expires,
        )
        current_db_session = db_session.object_session(upstream_refresh_token)
        current_db_session.add(upstream_refresh_token)
        db_session.commit()
