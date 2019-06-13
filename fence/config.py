import os
from yaml import safe_load as yaml_load
import urlparse

import cirrus
from gen3config import Config


DEFAULT_CFG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
)


class FenceConfig(Config):
    def post_process(self):
        # backwards compatibility if no new YAML cfg provided
        # these cfg use to be in settings.py so we need to make sure they gets defaulted
        default_config = yaml_load(
            open(
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
                )
            )
        )

        defaults = [
            "APPLICATION_ROOT",
            "AUTHLIB_INSECURE_TRANSPORT",
            "SESSION_COOKIE_SECURE",
            "ACCESS_TOKEN_COOKIE_NAME",
            "SESSION_COOKIE_NAME",
            "OAUTH2_TOKEN_EXPIRES_IN",
            "ACCESS_TOKEN_EXPIRES_IN",
            "REFRESH_TOKEN_EXPIRES_IN",
            "SESSION_TIMEOUT",
            "SESSION_LIFETIME",
            "GOOGLE_SERVICE_ACCOUNT_KEY_FOR_URL_SIGNING_EXPIRES_IN",
            "GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN",
            "GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN",
            "ACCESS_TOKEN_EXPIRES_IN",
            "dbGaP",
            "CIRRUS_CFG",
        ]
        for default in defaults:
            self.force_default_if_none(default, default_cfg=default_config)

        if "ROOT_URL" not in self._configs and "BASE_URL" in self._configs:
            url = urlparse.urlparse(self._configs["BASE_URL"])
            self._configs["ROOT_URL"] = "{}://{}".format(url.scheme, url.netloc)

        # allow authlib traffic on http for development if enabled. By default
        # it requires https.
        #
        # NOTE: use when fence will be deployed in such a way that fence will
        #       only receive traffic from internal clients, and can safely use HTTP
        if (
            self._configs.get("AUTHLIB_INSECURE_TRANSPORT")
            and "AUTHLIB_INSECURE_TRANSPORT" not in os.environ
        ):
            os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"

        # if we're mocking storage, ignore the storage backends provided
        # since they'll cause errors if misconfigured
        if self._configs.get("MOCK_STORAGE", False):
            self._configs["STORAGE_CREDENTIALS"] = {}

        cirrus.config.config.update(**self._configs.get("CIRRUS_CFG", {}))


config = FenceConfig(DEFAULT_CFG_PATH)
