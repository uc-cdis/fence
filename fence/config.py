import os
from collections import Mapping
import glob
from yaml import safe_load as yaml_load
import urlparse

import cirrus

from fence.settings import CONFIG_SEARCH_FOLDERS

from logging import getLogger

logger = getLogger(__name__)


class Config(Mapping):
    """
    Configuration singleton that's instantiated on module load.
    Allows updating from a config file by using .update()
    """

    def __init__(self):
        self._configs = {}

    def get(self, key, *args):
        return self._configs.get(key, *args)

    def set(self, key, value):
        self._configs.__setitem__(key, value)

    def __setitem__(self, key, value):
        self._configs.__setitem__(key, value)

    def __contains__(self, key):
        return key in self._configs

    def __iter__(self):
        for key, value in self._configs.iteritems():
            yield key, value

    def __getitem__(self, key):
        return self._configs[key]

    def __delitem__(self, key):
        del self._configs[key]

    def __len__(self):
        return len(self._configs)

    def __str__(self):
        return str(self._configs)

    def update(self, *args, **kwargs):
        """
        update configuration properties
        """
        self._configs.update(*args)
        self._configs.update(kwargs)

    def load(self, config_path=None, file_name=None):
        # TODO remove try, except when local_settings.py is no longer supported
        try:
            config_path = config_path or get_config_path(
                CONFIG_SEARCH_FOLDERS, file_name
            )
        except IOError:
            # TODO local_settings.py is being deprecated. Fow now, support
            # not proving a yaml configuration but log a warning.
            logger.warning(
                "No fence YAML configuration found. Will attempt "
                "to run without. If still using deprecated local_settings.py, you "
                "can ignore this warning but PLEASE upgrade to using the newest "
                "configuration format. local_settings.py is DEPRECATED!!"
            )
            config_path = None

        if config_path:
            self._load_configuration_files(config_path)

        if "ROOT_URL" not in self._configs:
            url = urlparse.urlparse(self._configs["BASE_URL"])
            self._configs["ROOT_URL"] = "{}://{}".format(url.scheme, url.netloc)

        # allow authlib traffic on http for development if enabled. By default
        # it requires https.
        #
        # NOTE: use when fence will be deployed in such a way that fence will
        #       only receive traffic from internal clients, and can safely use HTTP
        if self._configs.get("AUTHLIB_INSECURE_TRANSPORT"):
            os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"

        # if we're mocking storage, ignore the storage backends provided
        # since they'll cause errors if misconfigured
        if self._configs.get("MOCK_STORAGE", False):
            self._configs["STORAGE_CREDENTIALS"] = {}

        # expand urls based on provided vars
        self._expand_base_url()
        self._expand_api_base_url()

        cirrus.config.config.update(**self._configs.get("CIRRUS_CFG", {}))

    def _load_configuration_files(self, provided_config_path):
        logger.info("Loading default configuration...")
        config = yaml_load(
            open(
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
                )
            )
        )

        logger.info("Loading configuration: {}".format(provided_config_path))
        provided_configurations = yaml_load(open(provided_config_path))

        # only update known configuration values. In the situation
        # where the provided config does not have a certain value,
        # the default will be used.
        common_keys = {
            key: value
            for (key, value) in config.iteritems()
            if key in provided_configurations
        }
        keys_to_update = {
            key: value
            for (key, value) in provided_configurations.iteritems()
            if key in common_keys
        }
        unknown_keys = {
            key: value
            for (key, value) in provided_configurations.iteritems()
            if key not in common_keys
        }

        config.update(keys_to_update)

        if unknown_keys:
            logger.warning(
                "Unknown key(s) {} found in {}. Will be ignored.".format(
                    unknown_keys.keys(), provided_config_path
                )
            )

        self._configs.update(config)

    def _expand_base_url(self):
        """
        Replaces {{BASE_URL}} in specific configuration vars with the actual
        balue of BASE_URL
        """
        server_name = self._configs.get("SERVER_NAME")
        if server_name:
            provided_value = self._configs["SERVER_NAME"]
            self._configs["SERVER_NAME"] = provided_value.replace(
                "{{BASE_URL}}", self._configs["BASE_URL"]
            )

        google_redirect = (
            self._configs.get("OPENID_CONNECT", {})
            .get("google", {})
            .get("redirect_url")
        )
        if google_redirect:
            provided_value = self._configs["OPENID_CONNECT"]["google"]["redirect_url"]
            self._configs["OPENID_CONNECT"]["google"][
                "redirect_url"
            ] = provided_value.replace("{{BASE_URL}}", self._configs["BASE_URL"])

        default_logout = self._configs.get("DEFAULT_LOGIN_URL")
        if default_logout:
            provided_value = self._configs["DEFAULT_LOGIN_URL"]
            self._configs["DEFAULT_LOGIN_URL"] = provided_value.replace(
                "{{BASE_URL}}", self._configs["BASE_URL"]
            )

        shib_url = self._configs.get("SSO_URL")
        if shib_url:
            provided_value = self._configs["SSO_URL"]
            self._configs["SSO_URL"] = provided_value.replace(
                "{{BASE_URL}}", self._configs["BASE_URL"]
            )

        access_token_url = (
            self._configs.get("OPENID_CONNECT", {})
            .get("fence", {})
            .get("client_kwargs", {})
            .get("redirect_uri")
        )
        if access_token_url:
            provided_value = self._configs["OPENID_CONNECT"]["fence"]["client_kwargs"][
                "redirect_uri"
            ]
            self._configs["OPENID_CONNECT"]["fence"]["client_kwargs"][
                "redirect_uri"
            ] = provided_value.replace("{{BASE_URL}}", self._configs["BASE_URL"])

        authlib_jwt_iss = self._configs.get("OAUTH2_JWT_ISS")
        if authlib_jwt_iss:
            provided_value = self._configs["OAUTH2_JWT_ISS"]
            self._configs["OAUTH2_JWT_ISS"] = provided_value.replace(
                "{{BASE_URL}}", self._configs["BASE_URL"]
            )

    def _expand_api_base_url(self):
        """
        Replaces {{api_base_url}} in specific configuration vars with the actual
        balue of api_base_url
        """
        api_base_url = (
            self._configs.get("OPENID_CONNECT", {}).get("fence", {}).get("api_base_url")
        )
        if api_base_url is not None:
            authorize_url = (
                self._configs.get("OPENID_CONNECT", {})
                .get("fence", {})
                .get("authorize_url")
            )
            if authorize_url:
                provided_value = self._configs["OPENID_CONNECT"]["fence"][
                    "authorize_url"
                ]
                self._configs["OPENID_CONNECT"]["fence"][
                    "authorize_url"
                ] = provided_value.replace("{{api_base_url}}", api_base_url)

            access_token_url = (
                self._configs.get("OPENID_CONNECT", {})
                .get("fence", {})
                .get("access_token_url")
            )
            if access_token_url:
                provided_value = self._configs["OPENID_CONNECT"]["fence"][
                    "access_token_url"
                ]
                self._configs["OPENID_CONNECT"]["fence"][
                    "access_token_url"
                ] = provided_value.replace("{{api_base_url}}", api_base_url)

            refresh_token_url = (
                self._configs.get("OPENID_CONNECT", {})
                .get("fence", {})
                .get("refresh_token_url")
            )
            if refresh_token_url:
                provided_value = self._configs["OPENID_CONNECT"]["fence"][
                    "refresh_token_url"
                ]
                self._configs["OPENID_CONNECT"]["fence"][
                    "refresh_token_url"
                ] = provided_value.replace("{{api_base_url}}", api_base_url)


def get_config_path(search_folders, file_name="*config.yaml"):
    """
    Return the path of a single configuration file ending in config.yaml
    from one of the search folders.

    NOTE: Will return the first match it finds. If multiple are found,
    this will error out.
    """
    possible_configs = []
    for folder in search_folders:
        config_path = os.path.join(folder, file_name)
        possible_files = glob.glob(config_path)
        possible_configs.extend(possible_files)

    if len(possible_configs) == 1:
        return possible_configs[0]
    elif len(possible_configs) > 1:
        raise IOError(
            "Multiple config.yaml files found: {}. Please specify which "
            'configuration to use with "python run.py -c some-config.yaml".'.format(
                str(possible_configs)
            )
        )
    else:
        raise IOError(
            "Could not find config.yaml. Searched in the following locations: "
            "{}".format(str(search_folders))
        )


config = Config()
