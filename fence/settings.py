from collections import OrderedDict
import os

from cdislogging import get_logger

logger = get_logger(__name__)
# default settings if local_settings is not present
BASE_URL = 'http://localhost/user'
APP_NAME = 'Gen3 Data Commons'

SESSION_COOKIE_SECURE = True

# ``local_settings"" is not installed under the fence module in produdction.
# Instead, it should be located at ``/var/www/local_settings.py``. If it is
# located elsewhere, use that location in ``imp.load_source`` instead of
# ``/var/www/local_settings.py``, just below.
try:
    # Import everything from ``local_settings``, if it exists.
    from local_settings import *
except ImportError:
    # If it doesn't, look in ``/var/www``.
    try:
        import imp
        imp.load_source('local_settings', '/var/www/local_settings.py')
    except IOError:
        logger.warn("local_settings is not found")


# Use this setting when fence will be deployed in such a way that fence will
# only receive traffic from internal (CDIS) clients, and can safely use HTTP.
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


APPLICATION_ROOT = '/user'
DEBUG = True
OAUTH2_PROVIDER_ERROR_URI = "/api/oauth2/errors"

#: ``ACCESS_TOKEN_EXPIRES_IN: int``
#: The number of seconds after an access token is issued until it expires.
ACCESS_TOKEN_EXPIRES_IN = 1200

#: ``ACCESS_TOKEN_COOKIE_NAME: str``
#: The name of the browser cookie in which the access token will be stored.
ACCESS_TOKEN_COOKIE_NAME = 'access_token'

#: ``REFRESH_TOKEN_EXPIRES_IN: int``
#: The number of seconds after a refresh token is issued until it expires.
REFRESH_TOKEN_EXPIRES_IN = 2592000

#: ``SESSION_TIMEOUT: int``
#: The number of seconds after which a browser session is considered stale.
SESSION_TIMEOUT = 1800

#: ``SESSION_LIFETIME: int``
#: The maximum session lifetime in seconds.
SESSION_LIFETIME = 28800

#: ``GOOGLE_SERVICE_ACCOUNT_KEY_FOR_URL_SIGNING_EXPIRES_IN: int``
#: The number of seconds the user's Google service account key used for
#: url signing will last before being expired/rotated
#: 30 days = 2592000 seconds
GOOGLE_SERVICE_ACCOUNT_KEY_FOR_URL_SIGNING_EXPIRES_IN = 2592000

#: ``GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN: int``
#: The number of seconds after a User's Google account is added to bucket
#: access until it expires.
GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN = 86400

#: ``SESSION_COOKIE_NAME: str``
#: The name of the browser cookie in which the session token will be stored.
#: Note that the session token also stores information for the
#: ``flask.session`` in the ``context`` field of the token.
SESSION_COOKIE_NAME = 'fence'

# ``JWT_KEYPAIRS`` is an ordered dictionary of entries ``kid:
# (public_key_filename, private_key_filename)`` mapping key ids to keypairs
# used for signing and verifying JWTs issued by fence. NOTE that the filenames
# should be relative to the root directory in fence.
JWT_KEYPAIR_FILES = OrderedDict([
    ('key-01', ('keys/jwt_public_key.pem', 'keys/jwt_private_key.pem')),
])
