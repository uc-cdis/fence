import os
import glob
from yaml import safe_load as yaml_load
from yaml.scanner import ScannerError
import urlparse

import cirrus
from jinja2 import Template


from fence.settings import CONFIG_SEARCH_FOLDERS

from cdislogging import get_logger

logger = get_logger(__name__)


class Config(dict):
    """
    Configuration singleton that's instantiated on module load.
    Allows updating from a config file by using .update()
    """

    def __init__(self):
        self._configs = {}

    def get(self, key, default=None):
        return self._configs.get(key, default)

    def set(self, key, value):
        self._configs.__setitem__(key, value)

    def setdefault(self, key, default=None):
        self._configs.setdefault(key, default)

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

        support passing dictionary or keyword args
        """
        if len(args) > 1:
            raise TypeError(
                "update expected at most 1 arguments, got {}".format(len(args))
            )

        if args:
            self._configs.update(dict(args[0]))

        self._configs.update(kwargs)

    def load(self, config_path=None, file_name=None):
        # TODO remove try, except when local_settings.py is no longer supported
        try:
            cfg_search_folders = CONFIG_SEARCH_FOLDERS
            if not cfg_search_folders:
                logger.warning(
                    "CONFIG_SEARCH_FOLDERS not set, this is required to "
                    "search for configuration. Will attempt to search in current directory."
                )
                cfg_search_folders = os.path.dirname(os.path.abspath(__file__))

            config_path = config_path or get_config_path(cfg_search_folders, file_name)
        except IOError:
            # TODO (DEPRECATE LOCAL_SETTINGS): actually raise error here.
            # Fow now, support not proving a yaml configuration but log a warning.
            logger.warning(
                "No YAML configuration found. Will attempt "
                "to run without. If still using deprecated local_settings.py, you "
                "can ignore this warning but PLEASE upgrade to using the newest "
                "configuration format. local_settings.py is DEPRECATED!!"
            )
            config_path = None

        if config_path:
            self._load_configuration_file(config_path)

        self._post_process()

    def _load_configuration_file(self, provided_config_path):
        logger.info("Finding default configuration...")
        default_cfg_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
        )
        config = yaml_load(open(default_cfg_path))

        logger.info("Applying configuration: {}".format(provided_config_path))

        # treat cfg as template and replace vars, returning an updated dict
        provided_configurations = nested_render(
            yaml_load(open(provided_config_path)), {}, {}
        )

        # only update known configuration values. In the situation
        # where the provided config does not have a certain value,
        # the default will be used.
        common_keys = {
            key: value
            for (key, value) in config.iteritems()
            if key in provided_configurations
        }
        keys_not_provided = {
            key: value
            for (key, value) in config.iteritems()
            if key not in provided_configurations
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

        if keys_not_provided:
            logger.warning(
                "Did not provide key(s) {} in {}. Will be set to default value(s) from {}.".format(
                    keys_not_provided.keys(), provided_config_path, default_cfg_path
                )
            )

        if unknown_keys:
            logger.warning(
                "Unknown key(s) {} found in {}. Will be ignored.".format(
                    unknown_keys.keys(), provided_config_path
                )
            )

        self._configs.update(config)

    def _post_process(self):
        """
        Do some post processing to the configuration (set env vars if necessary,
        do more complex modifications/changes to vars, etc.)

        Called after loading the configuration and doing the template-replace.
        """
        pass


def nested_render(cfg, fully_rendered_cfgs, replacements):
    """
    Template render the provided cfg by recurisevly replacing {{var}}'s which values
    from the current "namespace".

    The nested config is treated like nested namespaces where the inner variables
    are only available in current block and further nested blocks.

    Said the opposite way: the namespace with available vars that can be used
    includes the current block's vars and parent block vars.

    This means that you can do replacements for top-level
    (global namespaced) config vars anywhere, but you can only use inner configs within
    that block or further nested blocks.

    An example is worth a thousand words:

        ---------------------------------------------------------------------------------
        fence-config.yaml
        --------------------------------------------------------------------------------
        BASE_URL: 'http://localhost/user'
        OPENID_CONNECT:
          fence:
            api_base_url: 'http://other_fence/user'
            client_kwargs:
              redirect_uri: '{{BASE_URL}}/login/fence/login'
            authorize_url: '{{api_base_url}}/oauth2/authorize'
        THIS_WONT_WORK: '{{api_base_url}}/test'
        --------------------------------------------------------------------------------

    "redirect_uri" will become "http://localhost/user/login/fence/login"
        - BASE_URL is in the global namespace so it can be used in this nested cfg

    "authorize_url" will become "http://other_fence/user/oauth2/authorize"
        - api_base_url is in the current namespace, so it is available

    "THIS_WONT_WORK" will become "/test"
        - Why? api_base_url is not in the current namespace and so we cannot use that
          as a replacement. the configuration (instead of failing) will replace with
          an empty string

    Args:
        cfg (TYPE): Description
        fully_rendered_cfgs (TYPE): Description
        replacements (TYPE): Description

    Returns:
        dict: Configurations with template vars replaced
    """
    try:
        for key, value in cfg.iteritems():
            replacements.update(cfg)
            fully_rendered_cfgs[key] = {}
            fully_rendered_cfgs[key] = nested_render(
                value,
                fully_rendered_cfgs=fully_rendered_cfgs[key],
                replacements=replacements,
            )
            # new namespace, remove current vars (no longer available as replacements)
            for old_cfg, value in cfg.iteritems():
                replacements.pop(old_cfg, None)

        return fully_rendered_cfgs
    except AttributeError:
        # it's not a dict, so lets try to render it. But only if it's
        # truthy (which means there's actually something to replace)
        if cfg:
            t = Template(str(cfg))
            rendered_value = t.render(**replacements)
            try:
                cfg = yaml_load(rendered_value)
            except ScannerError:
                # it's not loading into yaml, so let's assume it's a string with special
                # chars such as: {}[],&*#?|:-<>=!%@\)
                #
                # in YAML, we have to "quote" a string with special chars.
                #
                # since yaml_load isn't loading from a file, we need to wrap the Python
                # str in actual quotes.
                cfg = yaml_load('"{}"'.format(rendered_value))

        return cfg


def get_config_path(search_folders, file_name="*config.yaml"):
    """
    Return the path of a single configuration file ending in config.yaml
    from one of the search folders.

    NOTE: Will return the first match it finds. If multiple are found,
    this will error out.
    """
    possible_configs = []
    file_name = file_name or "*config.yaml"

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


class FenceConfig(Config):
    def __init__(self, *args, **kwargs):
        super(FenceConfig, self).__init__(*args, **kwargs)

    def _post_process(self):
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
            self._set_default(default, default_config=default_config)

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

    def _set_default(self, key, default_config=None, allow_none=False):
        default_config = default_config or yaml_load(
            open(
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
                )
            )
        )

        if key not in self._configs or (not allow_none and self._configs[key] is None):
            self._configs[key] = default_config.get(key)


config = FenceConfig()
