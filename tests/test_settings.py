from collections import OrderedDict
from cryptography.fernet import Fernet
from datetime import timedelta

from fence.local_settings import *


DB = 'postgresql://postgres@localhost:5432/fence_test'

MOCK_AUTH = True

DEBUG = False
OAUTH2_PROVIDER_ERROR_URI = "/oauth2/errors"

HOST_NAME = 'https://bionimbus-pdc.opensciencedatacloud.org'
SHIBBOLETH_HEADER = 'persistent_id'
SSO_URL = 'https://itrusteauth.nih.gov/affwebservices/public/saml2sso?SPID=https://bionimbus-pdc.opensciencedatacloud.org/shibboleth&RelayState='
SINGLE_LOGOUT = 'https://itrusteauth.nih.gov/siteminderagent/smlogout.asp?mode=nih&AppReturnUrl=https://bionimbus-pdc.opensciencedatacloud.org/storage/login'

LOGOUT = "https://bionimbus-pdc.opensciencedatacloud.org/auth/logout/?next=/Shibboleth.sso/Logout%3Freturn%3Dhttps%3A%2F%2Fbionimbus-pdc.opensciencedatacloud.org/api"
BIONIMBUS_ACCOUNT_ID = 123456789012

SESSION_TIMEOUT = timedelta(seconds=1800)
SESSION_LIFETIME = timedelta(seconds=28800)
HMAC_ENCRYPTION_KEY = Fernet.generate_key()
ENABLE_CSRF_PROTECTION = False
SESSION_COOKIE_NAME = "fence"

JWT_KEYPAIR_FILES = OrderedDict([
    (
        'key-test',
        ('resources/keys/test_public_key.pem', 'resources/keys/test_private_key.pem'),
    ),
    (
        'key-test-2',
        ('resources/keys/test_public_key_2.pem', 'resources/keys/test_private_key_2.pem'),
    ),
])

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
    "bucket3": "CRED1"
}
