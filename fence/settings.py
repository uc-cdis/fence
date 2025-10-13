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
