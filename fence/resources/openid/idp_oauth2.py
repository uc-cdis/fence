from authlib.client import OAuth2Session
from cached_property import cached_property
from jose import jwt
import requests


class Oauth2ClientBase(object):
    """
    An generic oauth2 client class for interacting with an Identity Provider
    """

    def __init__(self, settings, logger, scope, discovery_url, idp, HTTP_PROXY=None):
        self.logger = logger
        self.settings = settings
        self.session = OAuth2Session(
            client_id=settings["client_id"],
            client_secret=settings["client_secret"],
            scope=scope,
            redirect_uri=settings["redirect_url"],
        )
        # self.discovered_data = requests.get(discovery_url)
        self.idp = idp
        self.HTTP_PROXY = HTTP_PROXY

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
            elif return_value != default_value:
                self.logger.info(
                    "{}'s {}, {} differs from our "
                    "default {}. Using {}'s...".format(
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
            return_value = default_value

        return return_value

    def get_auth_url(self):
        """
        Must implement in inheriting class. Should return OAuth 2 Authorization URL.
        """
        raise NotImplementedError()

    def get_user_id(self, code):
        """
        Must implement in inheriting class. Should return dictionary with "email" field
        for successfully logged in user OR "error" field with details of the error.
        """
        raise NotImplementedError()