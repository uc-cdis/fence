"""
Fence Configuration Support Settings

NOTE TO DEVELOPERS: This is NOT intended to be a place for configurable variables.
                    Please put new cfg into the config-default.yaml

This exists primarily as a legacy support for old configuration, but has been
repurposed to hold some info used when searching for a provided configuration variable.
"""
from os.path import expanduser

# Folders to look in for the *config.yaml for fence
CONFIG_SEARCH_FOLDERS = ["/var/www/fence", "{}/.gen3/fence".format(expanduser("~"))]

# PLEASE USE NEW config-default.yaml FOR CONFIGURATION VARIABLES, NOT THIS FILE!

# WARNING: USE OF local_settings.py IS DEPRECATED.
#          WILL BE REMOVED IN FUTURE RELEASE.
# TODO (DEPRECATE LOCAL_SETTINGS): remove this entire block
#
# Please convert to using new configuration yaml file in one of the
# CONFIG_SEARCH_FOLDERS.
#
# ``local_settings"" is not installed under the fence module in produdction.
# Instead, it should be located at ``/var/www/local_settings.py``. If it is
# located elsewhere, use that location in ``imp.load_source`` instead of
# ``/var/www/local_settings.py``, just below.
def use_deprecated_settings():
    ENCRYPTION_KEY = HMAC_ENCRYPTION_KEY


try:
    # Import everything from ``local_settings``, if it exists.
    from local_settings import *

    use_deprecated_settings()
except ImportError:
    # If it doesn't, look in ``/var/www/fence``.
    try:
        import imp

        imp.load_source("local_settings", "/var/www/fence/local_settings.py")
        use_deprecated_settings()
    except IOError:
        pass
