from oauth2client.client import OAuth2WebServerFlow
import httplib2
import json


class Oauth2Client(object):
    """client for interacting with google oauth 2,
    as google openid connect is supported under oauth2"""

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
            r = http.request(
                "https://www.googleapis.com/plus/v1/people/me/openIdConnect"
            )
            if len(r) > 1:
                user_profile = json.loads(r[1])
                if user_profile.get("email_verified") == "true":
                    return {"email": user_profile["email"]}
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
