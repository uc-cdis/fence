import os
from boto.s3.connection import OrdinaryCallingFormat
DB = 'postgresql://test:test@localhost:5432/fence'

MOCK_AUTH = False
MOCK_STORAGE = False

BASE_URL = 'http://localhost/user'
APPLICATION_ROOT = '/user'

EMAIL_SERVER = 'localhost'

SEND_FROM = 'phillis.tt@gmail.com'

SEND_TO = 'phillis.tt@gmail.com'

HMAC_ENCRYPTION_KEY = ''

DEFAULT_LOGIN_URL = BASE_URL + '/login/google'
DEFAULT_LOGIN_URL_REDIRECT_PARAM = 'redirect'

OPENID_CONNECT = {
    'google': {
        'client_id': '',
        'client_secret': '',
        'redirect_url': ''
    },
    'fence': {
        'client_id': '',
        'client_secret': '',
        'api_base_url': '',
        'authorize_url': '',
        'access_token_url': '',
        'refresh_token_url': '',
        'client_kwargs': {
            'scope': 'openid user',
            'redirect_uri': '',
        },
    },
}

STORAGE_CREDENTIALS = {
    "cleversafe-server-a": {
        'backend': 'cleversafe',
        'aws_access_key_id': '',
        'aws_secret_access_key': '',
        'host': 'somemanager.osdc.io',
        'public_host': 'someobjstore.datacommons.io',
        'port': 443,
        'is_secure': True,
        'username': 'someone',
        'password': 'somepass',
        "calling_format": OrdinaryCallingFormat(),
        "is_mocked": True
    }
}

# Configuration necessary for cirrus (Cloud Management Library)
# https://github.com/uc-cdis/cirrus
# will eventually be passed as params but cirrus looks for env vars right now
os.environ["GOOGLE_API_KEY"] = ""
os.environ["GOOGLE_PROJECT_ID"] = ""
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = ""
os.environ["GOOGLE_ADMIN_EMAIL"] = ""
os.environ["GOOGLE_IDENTITY_DOMAIN"] = ""
os.environ["GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL"] = ""


'''
If the api is behind firewall that need to set http proxy:
    HTTP_PROXY = {'host': 'cloud-proxy', 'port': 3128}
'''
HTTP_PROXY = None

STORAGES = ['/cleversafe']

SHIBBOLETH_HEADER = 'persistent_id'

# assumes shibboleth is deployed under {BASE_URL}/shibboleth
SSO_URL = 'https://auth.nih.gov/affwebservices/public/saml2sso?SPID={}/shibboleth&RelayState='.format(BASE_URL)

ITRUST_GLOBAL_LOGOUT = 'https://auth.nih.gov/siteminderagent/smlogout.asp?mode=nih&AppReturnUrl='

SESSION_COOKIE_SECURE = False
ENABLE_CSRF_PROTECTION = True
INDEXD = '/index'

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

#: Confiure which identity providers this fence instance can use for login.
#:
#: See ``fence/blueprints/login/__init__.py`` for which identity providers can
#: be loaded.
ENABLED_IDENTITY_PROVIDERS = {
    'fence',
    'google',
    'shib',
}

# Hostname of a second fence instance to use as an IDP.
MULTI_TENANT_FENCE_HOSTNAME = 'http://localhost/user'
