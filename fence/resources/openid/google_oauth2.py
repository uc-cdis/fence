from oauth2client.client import OAuth2WebServerFlow

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
        self.flow = OAuth2WebServerFlow(
            client_id=settings["client_id"],
            client_secret=settings["client_secret"],
            scope="openid email",
            redirect_uri=settings["redirect_url"],
        )
        self.auth_url = self.get_auth_url()
        self.HTTP_PROXY = HTTP_PROXY

    def get_auth_url(self):
        return self.flow.step1_get_authorize_url()

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

            userinfo_endpoint = self.get_userinfo_endpoint()

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

    def get_userinfo_endpoint(self):
        """
        Return the url for Google's Userinfo endpoint by the recommended method of
        using their discovery url. Default to current userinfo url as identified
        09 JAN 2019.
        """
        default_userinfo = "https://openidconnect.googleapis.com/v1/userinfo"

        document = requests.get(self.GOOGLE_DISCOVERY_URL)

        if document.status_code == requests.codes.ok:
            userinfo_endpoint = document.json().get("userinfo_endpoint")
            if not userinfo_endpoint:
                logger.warning(
                    "could not retrieve `userinfo_endpoint` from Google response {}. "
                    "Defaulting to {}".format(document.json(), default_userinfo)
                )
                userinfo_endpoint = default_userinfo
            elif userinfo_endpoint != default_userinfo:
                logger.info(
                    "Google's userinfo endpoint {} differs from our "
                    "default {}. Using Google's...".format(
                        userinfo_endpoint, default_userinfo
                    )
                )
        else:
            logger.error(
                "{} ERROR from Google API, could not retrieve `userinfo_endpoint` from "
                "Google response {}. Defaulting to {}".format(
                    document.status_code, document, default_userinfo
                )
            )
            userinfo_endpoint = default_userinfo

        return userinfo_endpoint
