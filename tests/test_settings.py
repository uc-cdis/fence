from collections import OrderedDict
from cryptography.fernet import Fernet

from cdislogging import get_logger

logger = get_logger(__name__)

try:
    from fence.local_settings import *
except ImportError:
    logger.warn('no module fence.local_settings')


# WARNING: the test database is cleared every run
DB = 'postgresql://postgres@localhost:5432/fence_test_tmp'

MOCK_AUTH = True

DEBUG = False
OAUTH2_PROVIDER_ERROR_URI = "/oauth2/errors"

BASE_URL = 'https://bionimbus-pdc.opensciencedatacloud.org/user'
APPLICATION_ROOT = '/user'

SHIBBOLETH_HEADER = 'persistent_id'
SSO_URL = 'https://itrusteauth.nih.gov/affwebservices/public/saml2sso?SPID=https://bionimbus-pdc.opensciencedatacloud.org/shibboleth&RelayState='
SINGLE_LOGOUT = 'https://itrusteauth.nih.gov/siteminderagent/smlogout.asp?mode=nih&AppReturnUrl=https://bionimbus-pdc.opensciencedatacloud.org/storage/login'
ITRUST_GLOBAL_LOGOUT = 'https://auth.nih.gov/siteminderagent/smlogout.asp?mode=nih&AppReturnUrl='

LOGOUT = "https://bionimbus-pdc.opensciencedatacloud.org/auth/logout/?next=/Shibboleth.sso/Logout%3Freturn%3Dhttps%3A%2F%2Fbionimbus-pdc.opensciencedatacloud.org/api"
BIONIMBUS_ACCOUNT_ID = 123456789012

#: ``ACCESS_TOKEN_EXPIRES_IN: int``
#: The number of seconds after an access token is issued until it expires.
ACCESS_TOKEN_EXPIRES_IN = 1200

#: ``ACCESS_TOKEN_COOKIE_NAME: str``
#: The name of the browser cookie in which the access token will be stored.
ACCESS_TOKEN_COOKIE_NAME = 'access_token'

#: ``REFRESH_TOKEN_EXPIRES_IN: int``
#: The number of seconds after a refresh token is issued until it expires.
REFRESH_TOKEN_EXPIRES_IN = 1728000

#: ``SESSION_TIMEOUT: int``
#: The number of seconds after which a browser session is considered stale.
SESSION_TIMEOUT = 1800

#: ``SESSION_LIFETIME: int``
#: The maximum session lifetime in seconds.
SESSION_LIFETIME = 28800

#: ``GOOGLE_SERVICE_ACCOUNT_KEY_FOR_URL_SIGNING_EXPIRES_IN: int``
#: The number of seconds the user's Google service account key used for
#: url signing will last before being expired/rotated
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

HMAC_ENCRYPTION_KEY = Fernet.generate_key()
ENABLE_CSRF_PROTECTION = False

#: The test app uses the RSA key fixtures from authutils, so leave this empty.
JWT_KEYPAIR_FILES = OrderedDict([])

STORAGE_CREDENTIALS = {
    'test-cleversafe': {
        'backend': 'cleversafe'
    }
}

AWS_CREDENTIALS = {
    "CRED1": {
        'aws_access_key_id': '',
        'aws_secret_access_key': ''
    },
    "CRED2": {
        'aws_access_key_id': '',
        'aws_secret_access_key': ''
    }
}

S3_BUCKETS = {
    "bucket1": "CRED1",
    "bucket2": "CRED2",
    "bucket3": "CRED1",
    "bucket4": "*",
}

ENABLED_IDENTITY_PROVIDERS = {
    # ID for which of the providers to default to.
    'default': 'google',
    # Information for identity providers.
    'providers': {
        'fence': {
            'name': 'Fence Multi-Tenant OAuth',
        },
        'google': {
            'name': 'Google OAuth',
        },
        'shibboleth': {
            'name': 'NIH Login',
        },
    },
}

SHIBBOLETH_HEADER = 'persistent_id'

OPENID_CONNECT = {
    'google': {
        'client_id': '',
        'client_secret': '',
        'redirect_url': ''
    },
}
