import os

#: ``CONFIG_SEARCH_FOLDERS: List(str)``
#: Folders to look in for the config.yaml for fence
CONFIG_SEARCH_FOLDERS = [
    '/var/www/fence',
    '/etc/gen3/fence'
]

#: ``ACCESS_TOKEN_COOKIE_NAME: str``
#: The name of the browser cookie in which the access token will be stored.
ACCESS_TOKEN_COOKIE_NAME = 'access_token'

APPLICATION_ROOT = "/user"
DEBUG = True

OAUTH2_PROVIDER_ERROR_URI = "/api/oauth2/errors"

OAUTH2_TOKEN_EXPIRES_IN = {"authorization_code": 1200, "implicit": 1200}

#: ``ACCESS_TOKEN_EXPIRES_IN: int``
#: The number of seconds after an access token is issued until it expires.
ACCESS_TOKEN_EXPIRES_IN = 1200

#: ``ACCESS_TOKEN_COOKIE_NAME: str``
#: The name of the browser cookie in which the access token will be stored.
ACCESS_TOKEN_COOKIE_NAME = "access_token"

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

#: ``GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN: int``
#: The number of seconds after a User's Google Service account is added to bucket
#: access until it expires.
#: 7 days = 604800 seconds
GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN = 604800

# Use this setting when fence will be deployed in such a way that fence will
# only receive traffic from internal (CDIS) clients, and can safely use HTTP.
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'

