from cdislogging import get_logger
from collections import OrderedDict
from datetime import timedelta
import os

logger = get_logger(__name__)
# default settings if local_settings is not present
BASE_URL = 'http://localhost/user'
# local_settings is not installed under fence module in prod
try:
    from local_settings import *
except:
    logger.warn("local_settings is not found")



# Use this setting when fence will be deployed in such a way that fence will
# only receive traffic from internal (CDIS) clients, and can safely use HTTP.
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


APPLICATION_ROOT = '/user'
DEBUG = True
OAUTH2_PROVIDER_ERROR_URI = "/api/oauth2/errors"


LONG_ACCESS_TOKEN_EXPIRES_IN = 2592000
LONG_ACCESS_TOKEN_LIFETIME = timedelta(seconds=2592000)  # for backwards-compatibility

ACCESS_TOKEN_EXPIRES_IN = 1200
ACCESS_TOKEN_LIFETIME = timedelta(seconds=1200)  # for backwards-compatibility
ACCESS_TOKEN_COOKIE_NAME = "access_token"

REFRESH_TOKEN_EXPIRES_IN = 1728000


# stale session time
SESSION_TIMEOUT = timedelta(seconds=1800)
# max session lifetime
SESSION_LIFETIME = timedelta(seconds=28800)
SESSION_COOKIE_NAME = "fence"

# ``JWT_KEYPAIRS`` is an ordered dictionary of entries ``kid:
# (public_key_filename, private_key_filename)`` mapping key ids to keypairs
# used for signing and verifying JWTs issued by fence. NOTE that the filenames
# should be relative to the root directory in fence.
JWT_KEYPAIR_FILES = OrderedDict([
    ('key-01', ('keys/jwt_public_key.pem', 'keys/jwt_private_key.pem')),
])
