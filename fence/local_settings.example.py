import os
import json
from boto.s3.connection import OrdinaryCallingFormat


DB = 'postgresql://test:test@localhost:5432/fence'

MOCK_AUTH = False
MOCK_STORAGE = False

SERVER_NAME = 'http://localhost/user'
BASE_URL = SERVER_NAME
APPLICATION_ROOT = '/user'

ROOT_DIR = '/fence'

# If using multi-tenant setup, configure this to the base URL for the provider
# fence (i.e. ``BASE_URL`` in the provider fence config).
# OIDC_ISSUER = 'http://localhost:8080/user

EMAIL_SERVER = 'localhost'

SEND_FROM = 'phillis.tt@gmail.com'

SEND_TO = 'phillis.tt@gmail.com'

HMAC_ENCRYPTION_KEY = ''

DEFAULT_LOGIN_URL = BASE_URL + '/login/google'

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
    'cleversafe-server-a': {
        'backend': 'cleversafe',
        'aws_access_key_id': '',
        'aws_secret_access_key': '',
        'host': 'somemanager.osdc.io',
        'public_host': 'someobjstore.datacommons.io',
        'port': 443,
        'is_secure': True,
        'username': 'someone',
        'password': 'somepass',
        'calling_format': OrdinaryCallingFormat(),
        'is_mocked': True
    }
}

# Configuration necessary for cirrus (Cloud Management Library)
# https://github.com/uc-cdis/cirrus
# will eventually be passed as params but cirrus looks for env vars right now
CIRRUS_CFG = {
    'GOOGLE_API_KEY': '',
    'GOOGLE_PROJECT_ID': '',
    'GOOGLE_APPLICATION_CREDENTIALS': '',
    'GOOGLE_STORAGE_CREDS': '',
    'GOOGLE_ADMIN_EMAIL': '',
    'GOOGLE_IDENTITY_DOMAIN': '',
    'GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL': ''
}

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
    'CRED1': {
        'aws_access_key_id': '',
        'aws_secret_access_key': ''
    },
    'CRED2': {
        'aws_access_key_id': '',
        'aws_secret_access_key': ''
    }
}

S3_BUCKETS = {
    'bucket1': 'CRED1',
    'bucket2': 'CRED2',
    'bucket3': 'CRED1'
}

#: Confiure which identity providers this fence instance can use for login.
#:
#: See ``fence/blueprints/login/__init__.py`` for which identity providers can
#: be loaded.
#:
#: NOTE: Don't enable shibboleth if the deployment is not protected by
#: shibboleth module, the shib module takes care of preventing header spoofing.
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

APP_NAME = ''

#: ``MAX_PRESIGNED_URL_TTL: int``
#: The number of seconds after a pre-signed url is issued until it expires.
MAX_PRESIGNED_URL_TTL = 3600

#: ``MAX_API_KEY_TTL: int``
#: The number of seconds after an API KEY is issued until it expires.
MAX_API_KEY_TTL = 2592000

#: ``MAX_ACCESS_TOKEN_TTL: int``
#: The number of seconds after an access token is issued until it expires.
MAX_ACCESS_TOKEN_TTL = 3600
dir_path = "/secrets"
fence_creds = os.path.join(dir_path, 'fence_credentials.json')

if os.path.exists(fence_creds):
    with open(fence_creds, 'r') as f:
        data = json.load(f)
        AWS_CREDENTIALS = data['AWS_CREDENTIALS']
        S3_BUCKETS = data['S3_BUCKETS']
        DEFAULT_LOGIN_URL = data['DEFAULT_LOGIN_URL']
        OPENID_CONNECT.update(data['OPENID_CONNECT'])
        OIDC_ISSUER = data['OIDC_ISSUER']
        ENABLED_IDENTITY_PROVIDERS = data['ENABLED_IDENTITY_PROVIDERS']
        APP_NAME = data['APP_NAME']
        HTTP_PROXY = data['HTTP_PROXY']
        dbGaP = data["dbGaP"]
