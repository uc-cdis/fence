import os
from boto.s3.connection import OrdinaryCallingFormat

#: The URI for the database connection to use. In general fence assumes it is
#: using postgres for the database backend.
DB = 'postgresql://test:test@localhost:5432/fence'

#: Use for local testing. If ``MOCK_AUTH`` is enabled, functions will assume
#: the user is authenticated.
MOCK_AUTH = False

#: Also use for local testing. If enabled, the sto
MOCK_STORAGE = False

#: Set to the full URL of where fence will be hosted.
BASE_URL = 'http://localhost/user'

#: Set to the path component of ``BASE_URL``.
APPLICATION_ROOT = '/user'

#: If using multi-tenant setup, configure this to the base URL for the provider
#: fence (i.e. ``BASE_URL`` in the provider fence config).
#:
#: (Multi-tenant setup: this instance of fence is using another fence as its
#: identity provider, or IDP.)
OIDC_ISSUER = None

#: The default URL *in fence* to use as the IDP.
DEFAULT_LOGIN_URL = BASE_URL + '/login/google'

#: The name for the parameter on the default login URL that takes the redirect
#: argument.
DEFAULT_LOGIN_URL_REDIRECT_PARAM = 'redirect'

#: Settings for enabling OpenID Connect.
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

#: Confiure which identity providers this fence instance can use for login.
#:
#: See ``fence/blueprints/login/__init__.py`` for which identity providers can
#: be loaded.
#:
#: NOTE: Don't enable shibboleth if the deployment is not protected by
#: shibboleth module, the shibboleth module takes care of preventing header
#: spoofing.
ENABLED_IDENTITY_PROVIDERS = {
    # ID for which of the providers to default to (a key in ``providers``).
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

#: "SSO" == single sign-on.
#: Assumes fence shibboleth endpoint is deployed under
#: ``{BASE_URL}/shibboleth``.
SSO_URL = (
    'https://auth.nih.gov/affwebservices/public/saml2sso'
    '?SPID={}/shibboleth'
    '&RelayState='
).format(BASE_URL)

#: If the IDP for the current user session is ITrust, fence will redirect to
#: this URL.
ITRUST_GLOBAL_LOGOUT = (
    'https://auth.nih.gov/siteminderagent/smlogout.asp'
    '?mode=nih'
    '&AppReturnUrl='
)

#: Credentials used to set up a ``StorageManager`` (see
#: ``fence/resources/storage/``).
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

#: Which storage backends are supported, written as endpoints for the storage
#: blueprint.
STORAGES = ['/cleversafe']

#: Configuration necessary for cirrus (Cloud Management Library)
#:
#:     https://github.com/uc-cdis/cirrus
#:
#: Will eventually be passed as params but cirrus looks for env vars right now.
os.environ["GOOGLE_API_KEY"] = ""
os.environ["GOOGLE_PROJECT_ID"] = ""
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = ""
os.environ["GOOGLE_ADMIN_EMAIL"] = ""
os.environ["GOOGLE_IDENTITY_DOMAIN"] = ""
os.environ["GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL"] = ""

#: Use if the api is behind a firewall that needs to set HTTP proxy. Example:
#:
#:     HTTP_PROXY = {'host': 'cloud-proxy', 'port': 3128}
HTTP_PROXY = None

#: Whether the CSRF token cookie should be HTTPS-only. Use ``False`` (HTTP) for
#: local testing and ``True`` for everything else.
SESSION_COOKIE_SECURE = False

#: If set to ``False``, fence will skip the CSRF token check. Set to ``false``
#: for tests and ``True`` for everything else.
ENABLE_CSRF_PROTECTION = True

#: Set to the URL of the indexd service that is running:
#:
#:     http://github.com/uc-cdis/indexd
#:
#: To generate presigned URLs for downloading or uploading data, fence gets the
#: storage URLs for a requested file ID from indexd.
INDEXD = '/index'

#: Mapping from S3 bucket URLs to their associated credentials name. These
#: names should correspond to entries in ``AWS_CREDENTIALS``, below. Used for
#: generating presigned URLs to download files from buckets in AWS S3.
S3_BUCKETS = {
    "bucket1": "CRED1",
    "bucket2": "CRED2",
    "bucket3": "CRED1"
}

#: Mapping from credentials names to AWS secret keys and IDs.
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

#: ``MAX_PRESIGNED_URL_TTL: int``
#: The number of seconds after a pre-signed url is issued until it expires.
MAX_PRESIGNED_URL_TTL = 3600

#: ``MAX_API_KEY_TTL: int``
#: The number of seconds after an API KEY is issued until it expires.
MAX_API_KEY_TTL = 2592000

#: ``MAX_ACCESS_TOKEN_TTL: int``
#: The number of seconds after an access token is issued until it expires.
MAX_ACCESS_TOKEN_TTL = 3600

EMAIL_SERVER = 'localhost'

SEND_FROM = 'example@gmail.com'

SEND_TO = 'example@gmail.com'
