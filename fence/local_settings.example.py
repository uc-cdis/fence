import os
import json
from boto.s3.connection import OrdinaryCallingFormat


DB = "postgresql://test:test@localhost:5432/fence"

MOCK_AUTH = False
MOCK_STORAGE = False

SERVER_NAME = "http://localhost/user"
BASE_URL = SERVER_NAME
APPLICATION_ROOT = "/user"

ROOT_DIR = "/fence"

# If using multi-tenant setup, configure this to the base URL for the provider
# fence (i.e. ``BASE_URL`` in the provider fence config).
# OIDC_ISSUER = 'http://localhost:8080/user

EMAIL_SERVER = "localhost"

SEND_FROM = "phillis.tt@gmail.com"

SEND_TO = "phillis.tt@gmail.com"

HMAC_ENCRYPTION_KEY = ""

DEFAULT_LOGIN_URL = BASE_URL + "/login/google"

OPENID_CONNECT = {
    "google": {
        "client_id": "",
        "client_secret": "",
        "redirect_url": "",
        "name": "Google",
    },
    "fence": {
        "client_id": "",
        "client_secret": "",
        "api_base_url": "FENCE_ROOT_ENDPOINT",
        "authorize_url": "FENCE_ROOT_ENDPOINT/oauth2/authorize",
        "access_token_url": "FENCE_ROOT_ENDPOINT/oauth2/token",
        "refresh_token_url": "FENCE_ROOT_ENDPOINT/oauth2/token",
        "client_kwargs": {
            "scope": "openid user",
            "redirect_uri": "BASE_URL/login/fence/login",
        },
        "name": "NIH",
    },
}

STORAGE_CREDENTIALS = {
    "cleversafe-server-a": {
        "backend": "cleversafe",
        "aws_access_key_id": "",
        "aws_secret_access_key": "",
        "host": "somemanager.osdc.io",
        "public_host": "someobjstore.datacommons.io",
        "port": 443,
        "is_secure": True,
        "username": "someone",
        "password": "somepass",
        "calling_format": OrdinaryCallingFormat(),
        "is_mocked": True,
    },
    "google-cloud-server": {
        "backend": "google",
        "google_project_id": "some-project-id-239870as9f23flkja8010",
    },
}

# Configuration necessary for cirrus (Cloud Management Library)
# https://github.com/uc-cdis/cirrus
# will eventually be passed as params but cirrus looks for env vars right now
CIRRUS_CFG = {
    "GOOGLE_API_KEY": "",
    "GOOGLE_PROJECT_ID": "",
    "GOOGLE_APPLICATION_CREDENTIALS": "",
    "GOOGLE_STORAGE_CREDS": "",
    "GOOGLE_ADMIN_EMAIL": "",
    "GOOGLE_IDENTITY_DOMAIN": "",
    "GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL": "",
}

"""
If the api is behind firewall that need to set http proxy:
    HTTP_PROXY = {'host': 'cloud-proxy', 'port': 3128}
"""
HTTP_PROXY = None
STORAGES = ["/cleversafe"]

SHIBBOLETH_HEADER = "persistent_id"

# assumes shibboleth is deployed under {BASE_URL}/shibboleth
SSO_URL = "https://auth.nih.gov/affwebservices/public/saml2sso?SPID={}/shibboleth&RelayState=".format(
    BASE_URL
)

ITRUST_GLOBAL_LOGOUT = (
    "https://auth.nih.gov/siteminderagent/smlogout.asp?mode=nih&AppReturnUrl="
)

SESSION_COOKIE_SECURE = False
ENABLE_CSRF_PROTECTION = True

INDEXD = "/index"

INDEXD_AUTH = ("gdcapi", "")

ARBORIST = "/rbac"

AWS_CREDENTIALS = {
    "CRED1": {"aws_access_key_id": "", "aws_secret_access_key": ""},
    "CRED2": {"aws_access_key_id": "", "aws_secret_access_key": ""},
}

ASSUMED_ROLES = {"arn:aws:iam::role1": "CRED1"}

DATA_UPLOAD_BUCKET = "bucket1"

S3_BUCKETS = {
    "bucket1": {"cred": "CRED1"},
    "bucket2": {"cred": "CRED2"},
    "bucket3": {"cred": "CRED1", "role-arn": "arn:aws:iam::role1"},
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
    "default": "google",
    # Information for identity providers. The name will be what show
    # up in portal login page
    "providers": {
        "fence": {"name": "NIH Login"},
        "google": {"name": "Google OAuth"},
        "shibboleth": {"name": "NIH Login"},
    },
}

APP_NAME = ""

GOOGLE_GROUP_PREFIX = ""

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
fence_creds = os.path.join(dir_path, "fence_credentials.json")

GOOGLE_MANAGED_SERVICE_ACCOUNT_DOMAINS = {
    "dataflow-service-producer-prod.iam.gserviceaccount.com",
    "cloudbuild.gserviceaccount.com",
    "cloud-ml.google.com.iam.gserviceaccount.com",
    "container-engine-robot.iam.gserviceaccount.com",
    "dataflow-service-producer-prod.iam.gserviceaccount.com",
    "sourcerepo-service-accounts.iam.gserviceaccount.com",
    "dataproc-accounts.iam.gserviceaccount.com",
    "gae-api-prod.google.com.iam.gserviceaccount.com",
    "genomics-api.google.com.iam.gserviceaccount.com",
    "containerregistry.iam.gserviceaccount.com",
    "container-analysis.iam.gserviceaccount.com",
    "cloudservices.gserviceaccount.com",
    "stackdriver-service.iam.gserviceaccount.com",
    "appspot.gserviceaccount.com",
    "partnercontent.gserviceaccount.com",
    "trifacta-gcloud-prod.iam.gserviceaccount.com",
    "gcf-admin-robot.iam.gserviceaccount.com",
    "compute-system.iam.gserviceaccount.com",
    "gcp-sa-websecurityscanner.iam.gserviceaccount.com",
    "storage-transfer-service.iam.gserviceaccount.com",
}

REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION = {
    "enable": False,
    "domain": "smtp domain",
    "subject": "User service account removal notification",
    "from": "do-not-reply@planx-pla.net",
    "admin": [],
    "contact number": "123456789",
    "content": """
    The service accounts were removed from access control data because some \
users or service accounts of GCP project {} are not authorized to access \
the data sets associated to the service accounts, or do not \
adhere to the security policies.
    """,
}

SUPPORT_EMAIL_FOR_ERRORS = None
dbGaP = {}
if os.path.exists(fence_creds):
    with open(fence_creds, "r") as f:
        data = json.load(f)
        AWS_CREDENTIALS = data["AWS_CREDENTIALS"]
        S3_BUCKETS = data["S3_BUCKETS"]
        DEFAULT_LOGIN_URL = data["DEFAULT_LOGIN_URL"]
        OPENID_CONNECT.update(data["OPENID_CONNECT"])
        OIDC_ISSUER = data["OIDC_ISSUER"]
        ENABLED_IDENTITY_PROVIDERS = data["ENABLED_IDENTITY_PROVIDERS"]
        APP_NAME = data["APP_NAME"]
        HTTP_PROXY = data["HTTP_PROXY"]
        dbGaP = data["dbGaP"]
        GOOGLE_GROUP_PREFIX = data.get("GOOGLE_GROUP_PREFIX")
        WHITE_LISTED_SERVICE_ACCOUNT_EMAILS = data.get(
            "WHITE_LISTED_SERVICE_ACCOUNT_EMAILS"
        )
        WHITE_LISTED_GOOGLE_PARENT_ORGS = data.get("WHITE_LISTED_GOOGLE_PARENT_ORGS")
        GOOGLE_MANAGED_SERVICE_ACCOUNT_DOMAINS.update(
            data.get("GOOGLE_MANAGED_SERVICE_ACCOUNT_DOMAINS", [])
        )
        GUN_MAIL = data.get("GUN_MAIL")
