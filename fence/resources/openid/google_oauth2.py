from authlib.client import OAuth2Session
import base64
import httplib2
import json
import requests
from cdislogging import get_logger

logger = get_logger(__name__)


class Oauth2Client(object):
    """
    client for interacting with google oauth 2,
    as google openid connect is supported under oauth2

    https://developers.google.com/api-client-library/python/guide/aaa_oauth
    """

    GOOGLE_DISCOVERY_URL = (
        "https://accounts.google.com/.well-known/openid-configuration"
    )

    def __init__(self, settings, logger, HTTP_PROXY=None):
        self.logger = logger
        self.settings = settings
        self.session = OAuth2Session(
            client_id=settings["client_id"],
            client_secret=settings["client_secret"],
            scope="openid email",
            redirect_uri=settings["redirect_url"],
        )
        self.discovered_data = requests.get(self.GOOGLE_DISCOVERY_URL)
        self.auth_url = self.get_auth_url()
        self.HTTP_PROXY = HTTP_PROXY

    def get_auth_url(self):
        authorization_endpoint = self.get_discovered_endpoint(
            "authorization_endpoint",
            "https://accounts.google.com/o/oauth2/v2/auth",
        )
        uri, _ = self.session.authorization_url(authorization_endpoint)

        return uri

    def get_user_id(self, code):
        token_endpoint = self.get_discovered_endpoint(
            "token_endpoint",
            "https://oauth2.googleapis.com/token",
        )

        try:
            proxies = None
            if self.HTTP_PROXY and self.HTTP_PROXY.get("host"):
                proxies = {
                    "http": "http://"
                    + self.HTTP_PROXY["host"]
                    + ":"
                    + str(self.HTTP_PROXY["port"])
                }
            token = self.session.fetch_token(
                url=token_endpoint, code=code, proxies=proxies
            )

            parts = token["id_token"].split(".")
            claims = json.loads(base64.b64decode(parts[1] + "==="))

            if claims["email"]:
                return {"email": claims["email"]}
            else:
                return {"error": "Can't get user's Google email!"}
        except Exception as e:
            self.logger.exception("Can't get user info")
        return {"error": "Can't get your Google email: {}".format(e)}

    def get_discovered_endpoint(self, endpoint_key, default_endpoint):
        """
        Return the url for Google's endpoint by the recommended method of
        using their discovery url. Default to current url as identified
        14 MAR 2019.
        """

        document = self.discovered_data
        return_value = default_endpoint

        if document.status_code == requests.codes.ok:
            return_value = document.json().get(endpoint_key)
            if not return_value:
                logger.warning(
                    "could not retrieve `{}` from Google response {}. "
                    "Defaulting to {}".format(
                        endpoint_key, document.json(), default_endpoint
                    )
                )
                return_value = default_endpoint
            elif return_value != default_endpoint:
                logger.info(
                    "ORCID's {}, {} differs from our "
                    "default {}. Using Google's...".format(
                        endpoint_key, return_value, default_endpoint
                    )
                )
        else:
            logger.error(
                "{} ERROR from Google API, could not retrieve `{}` from "
                "Google response {}. Defaulting to {}".format(
                    endpoint_key,
                    document.status_code,
                    document.json(),
                    default_endpoint,
                )
            )
            return_value = default_endpoint

        return return_value
