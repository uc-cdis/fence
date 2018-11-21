#: ``CONFIG_SEARCH_FOLDERS: List(str)``
#: Folders to look in for the *config.yaml for fence
from os.path import expanduser

# Folders to look in for the *config.yaml for fence
CONFIG_SEARCH_FOLDERS = ["/var/www/fence", "{}/.gen3/fence".format(expanduser("~"))]
