from authlib.client import OAuth2Session

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
        self.flow = OAuth2Session(
            client_id=settings["client_id"],
            client_secret=settings["client_secret"],
            scope="openid email",
            redirect_uri=settings["redirect_url"],
        )
        self.auth_url = self.get_auth_url()
        self.HTTP_PROXY = HTTP_PROXY

    def get_auth_url(self):
        self.get_endpoint_from_discovery_doc(
            "authorization_endpont",
            "https://openidconnect.googleapis.com/v1/authorization_endpoint",
        )

    def get_user_id(self, code):
        try:
            if self.HTTP_PROXY and self.HTTP_PROXY.get("host"):
                proxy = httplib2.ProxyInfo(
                    proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
                    proxy_host=self.HTTP_PROXY["host"],
                    proxy_port=self.HTTP_PROXY["port"],
                    proxy_rdns=True,
                )
                http = httplib2.Http(proxy_info=proxy)
            else:
                http = httplib2.Http()
            creds = self.flow.step2_exchange(code, http=http)
            http = creds.authorize(http)

            userinfo_endpoint = self.get_endpoint_from_discovery_doc(
                "userinfo_endpoint", "https://openidconnect.googleapis.com/v1/userinfo"
            )

            r = http.request(userinfo_endpoint)
            if len(r) > 1:
                user_profile = json.loads(r[1])
                if user_profile.get("email_verified"):
                    return {"email": user_profile.get("email")}
                else:
                    return {
                        "error": (
                            "Your email is not verified: {}".format(
                                user_profile.get("error", "")
                            )
                        )
                    }
            else:
                return {"error": "Can't get user's email"}
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get your email: {}".format(e)}

    def get_endpoint_from_discovery_doc(self, key, default_endpoint=None):
        """
        Return the url for Google's endpoint by the recommended method of
        using their discovery url.
        """

        document = requests.get(self.GOOGLE_DISCOVERY_URL)

        if document.status_code == requests.codes.ok:
            google_endpoint = document.json().get(key)
            if not google_endpoint:
                logger.warning(
                    "could not retrieve `{}` from Google response {}. "
                    "Defaulting to {}".format(key, document.json(), default_endpoint)
                )
                google_endpoint = default_endpoint
            elif google_endpoint != default_endpoint:
                logger.info(
                    "Google's endpoint {} differs from our "
                    "default {}. Using Google's...".format(
                        google_endpoint, default_endpoint
                    )
                )
        else:
            logger.error(
                "{} ERROR from Google API, could not retrieve `google_endpoint` from "
                "Google response {}. Defaulting to {}".format(
                    document.status_code, document, default_endpoint
                )
            )
            google_endpoint = default_endpoint

        return google_endpoint
