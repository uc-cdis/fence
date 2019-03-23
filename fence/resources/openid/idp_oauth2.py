from authlib.client import OAuth2Session
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
        self.discovery_url = discovery_url
        self.idp = idp
        self.HTTP_PROXY = HTTP_PROXY

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
            logger.error(
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
        using their discovery url. Default to current url as identified
        14 MAR 2019.
        """

        document = requests.get(self.discovery_url)
        return_value = default_value

        if document.status_code == requests.codes.ok:
            return_value = document.json().get(key)
            if not return_value:
                self.logger.warning(
                    "could not retrieve `{}` from {} response {}. "
                    "Defaulting to {}".format(
                        key, self.idp, document.json(), default_value
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
            self.logger.error(
                "{} ERROR from {} API, could not retrieve `{}` from response {}. Defaulting to {}".format(
                    document.status_code, self.idp, key, document.json(), default_value
                )
            )
            return_value = default_value

        return return_value
