import hashlib
from itsdangerous import Signer

# Explicitly set to sha256 as the default (sha1) will break in FIPS environments when flask_wtf attempts to process a user registration form.
# This is a known issue with itsdangerous defaults (see: https://github.com/pgadmin-org/pgadmin4/issues/7979 for a similar issue with pgadmin)
# According to: https://itsdangerous.palletsprojects.com/en/latest/concepts/#digest-method-security and https://stackoverflow.com/a/27669587, we can override the default here:
Signer.default_digest_method = hashlib.sha256

from collections import OrderedDict
import os
from urllib.parse import urljoin

from authutils.oauth2.client import OAuthClient
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError
from cdislogging import get_logger
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from gen3authz.client.arborist.client import ArboristClient
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from sqlalchemy.orm import scoped_session


# Can't read config yet. Just set to debug for now, else no handlers.
# Later, in app_config(), will actually set level based on config
logger = get_logger(__name__, log_level="debug")

# Load the configuration *before* importing modules that rely on it
from fence.config import config, CONFIG_SEARCH_FOLDERS

config.load(
    config_path=os.environ.get("FENCE_CONFIG_PATH"),
    search_folders=CONFIG_SEARCH_FOLDERS,
)

from fence.auth import logout, build_redirect_url
from fence.metrics import metrics
from fence.blueprints.data.indexd import S3IndexedFileLocation
from fence.blueprints.login.utils import allowed_login_redirects, domain
from fence.errors import UserError
from fence.jwt import keys
from fence.oidc.client import query_client
from fence.oidc.server import server
from fence.resources.audit.client import AuditServiceClient
from fence.resources.aws.boto_manager import BotoManager
from fence.resources.openid.idp_oauth2 import Oauth2ClientBase
from fence.resources.openid.cilogon_oauth2 import CilogonOauth2Client
from fence.resources.openid.cognito_oauth2 import CognitoOauth2Client
from fence.resources.openid.google_oauth2 import GoogleOauth2Client
from fence.resources.openid.microsoft_oauth2 import MicrosoftOauth2Client
from fence.resources.openid.okta_oauth2 import OktaOauth2Client
from fence.resources.openid.orcid_oauth2 import OrcidOauth2Client
from fence.resources.openid.synapse_oauth2 import SynapseOauth2Client
from fence.resources.openid.ras_oauth2 import RASOauth2Client
from fence.resources.storage import StorageManager
from fence.resources.user.user_session import UserSessionInterface
from fence.error_handler import get_error_response
from fence.utils import get_SQLAlchemyDriver
import fence.blueprints.admin
import fence.blueprints.data
import fence.blueprints.login
import fence.blueprints.oauth2
import fence.blueprints.misc
import fence.blueprints.storage_creds
import fence.blueprints.user
import fence.blueprints.well_known
import fence.blueprints.link
import fence.blueprints.google
import fence.blueprints.privacy
import fence.blueprints.register
import fence.blueprints.ga4gh


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["content-type", "accept"],
    expose_headers=["*"],
)


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Skips CSRF validation when:
      - An Authorization header is present (machine-to-machine / token auth)
      - There is no session username (unauthenticated request)
      - ENABLE_CSRF_PROTECTION is False in config
      - The HTTP method is GET (safe method)

    Otherwise validates either the x-csrf-token header or the csrf_token
    form field against the signed token stored in the session.
    """

    async def dispatch(self, request: Request, call_next):

        has_auth = "authorization" in request.headers
        session = request.session if hasattr(request, "session") else {}
        no_username = not session.get("username")

        if has_auth or no_username:
            return await call_next(request)

        if not config.get("ENABLE_CSRF_PROTECTION", True):
            return await call_next(request)

        if request.method == "GET":
            return await call_next(request)

        try:
            csrf_header = request.headers.get("x-csrf-token")
            form = await request.form()
            csrf_formfield = form.get("csrf_token")

            assert csrf_header is None or csrf_formfield is None

            referer = request.headers.get("referer")
            assert referer, "Referer header missing"
            logger.debug("HTTP REFERER " + str(referer))
        except Exception as e:
            raise UserError("CSRF verification failed: {}. Request aborted".format(e))

        return await call_next(request)


app.add_middleware(CSRFMiddleware)


def warn_about_logger():
    raise Exception(
        "Flask 0.12 will remove and replace all of our log handlers if you call "
        "app.logger anywhere. Use get_logger from cdislogging instead."
    )


def app_init(
    app: FastAPI,
    root_dir=None,
    config_path=None,
    config_file_name=None,
):
    app.__dict__["logger"] = warn_about_logger

    app_config(
        app,
        root_dir=root_dir,
        config_path=config_path,
        file_name=config_file_name,
    )
    app_sessions(app)

    app_register_routers(app)
    # app_register_blueprints(app)
    server.init_app(app, query_client=query_client)
    logger.info(
        f"Prometheus metrics are{'' if config['ENABLE_PROMETHEUS_METRICS'] else ' NOT'} enabled."
    )


def app_sessions(app):
    app.url_map.strict_slashes = False
    app.db = get_SQLAlchemyDriver(config["DB"])

    # app.db.Session is from SQLAlchemyDriver and uses
    # SQLAlchemy's sessionmaker. Using scoped_session here ensures
    # a thread-local db session is created. Effectively the below is expanded to:
    #   app.scoped_session = scoped_session(
    #       sessionmaker(
    #            bind=sqlalchemy.create_engine(config["DB"]),
    #            expire_on_commit=False,
    #       )
    #   )
    #
    # From the sqlalchemy docs: "The scoped_session object by default uses
    # [Python's threading.local() construct] as
    # storage, so that a single Session is maintained for all who call upon the
    # scoped_session registry, but only within the scope of a single thread.
    # Callers who call upon the registry in a different thread get a Session
    # instance that is local to that other thread."
    app.scoped_session = scoped_session(app.db.Session)

    app.session_interface = UserSessionInterface()


def app_register_routers(app: FastAPI):
    """
    Register API routers

    Args:
        app (FastAPI)
    """
    app.include_router(fence.blueprints.oauth2.router, prefix="/oauth2")
    app.include_router(fence.blueprints.user.router, prefix="/user")

    creds_router = fence.blueprints.storage_creds.make_creds_router()
    app.include_router(creds_router, prefix="/credentials")

    app.include_router(fence.blueprints.admin.router, prefix="/admin")
    app.include_router(fence.blueprints.well_known.router, prefix="/.well-known")

    login_router = fence.blueprints.login.make_login_router()
    app.include_router(login_router, prefix="/login")

    link_router = fence.blueprints.link.make_link_router()
    app.include_router(link_router, prefix="/link")

    google_router = fence.blueprints.google.make_google_router()
    app.include_router(google_router, prefix="/google")

    app.include_router(fence.blueprints.privacy.router, prefix="/privacy-policy")
    app.include_router(fence.blueprints.register.router, prefix="/register")
    app.include_router(fence.blueprints.ga4gh.router, prefix="/ga4gh")

    fence.blueprints.misc.register_misc(app)

    @app.get("/")
    async def root():
        """
        Register the root URL.
        """
        endpoints = {
            "oauth2 endpoint": "/oauth2",
            "user endpoint": "/user",
            "keypair endpoint": "/credentials",
        }
        return JSONResponse(endpoints)

    @app.get("/logout")
    async def logout_endpoint(
        request: Request, next: str = None, force_era_global_logout: str = "false"
    ):
        root = config.get("BASE_URL", "")
        request_next = next or root
        _force_era = force_era_global_logout == "true"
        if request_next.startswith("https") or request_next.startswith("http"):
            next_url = request_next
        else:
            next_url = build_redirect_url(config.get("ROOT_URL", ""), request_next)
        if domain(next_url) not in allowed_login_redirects():
            raise UserError("invalid logout redirect URL: {}".format(next_url))
        return logout(next_url=next_url, force_era_global_logout=_force_era)

    @app.get("/jwt/keys")
    async def public_keys():
        """
        Return the public keys which can be used to verify JWTs signed by fence.

        Response format:
            {
                "keys": [
                    ["<kid>", "<public key>"]
                ]
            }
        """
        return JSONResponse(
            {"keys": [(keypair.kid, keypair.public_key) for keypair in app.keypairs]}
        )

    @app.get("/metrics")
    async def metrics_endpoint():
        """
        WARNING: There is no authz control on this endpoint!
        In cloud-automation setups, access is blocked at the revproxy level.
        """
        data, content_type = metrics.get_latest_metrics()
        return Response(data, media_type=content_type)


def _check_azure_storage(app):
    """
    Confirm access to Azure Storage Account and Containers
    """
    azure_creds = config.get("AZ_BLOB_CREDENTIALS", None)

    # if this is a public bucket, Fence will not try to sign the URL
    if azure_creds == "*":
        return

    if not azure_creds or azure_creds.strip() == "":
        # Azure Blob credentials are not configured.
        # If you're using Azure Blob Storage set AZ_BLOB_CREDENTIALS to your Azure Blob Storage Connection String.
        logger.debug(
            "Azure Blob credentials are not configured.  If you're using Azure Blob Storage, please set AZ_BLOB_CREDENTIALS to your Azure Blob Storage Connection String."
        )
        return

    blob_service_client = BlobServiceClient.from_connection_string(azure_creds)

    for c in blob_service_client.list_containers():
        container_client = blob_service_client.get_container_client(c.name)

        # check if container exists.  If it doesn't exist, log a warning.
        if container_client.exists() is False:
            logger.debug(
                f"Unable to access Azure Blob Storage Container {c.name}. You may run into issues resolving orphaned indexed files pointing to this container."
            )
            continue

        # verify that you can check the container properties
        try:
            container_properties = container_client.get_container_properties()
            public_access = container_properties["public_access"]
            # check container properties
            logger.debug(
                f"Azure Blob Storage Container {c.name} has public access {public_access}"
            )
        except ResourceNotFoundError as err:
            logger.debug(
                f"Unable to access Azure Blob Storage Container {c.name}. You may run into issues resolving orphaned indexed files pointing to this container."
            )
            logger.debug(err)


def _check_buckets_aws_creds_and_region(app):
    """
    Function to ensure that all s3_buckets have a valid credential.
    Additionally, if there is no region it will produce a warning
    then try to fetch and cache the region.
    """
    buckets = config.get("S3_BUCKETS") or {}
    aws_creds = config.get("AWS_CREDENTIALS") or {}

    # check that AWS creds and regions are configured
    for bucket_name, bucket_details in buckets.items():
        cred = bucket_details.get("cred")
        region = bucket_details.get("region")
        if not cred:
            raise ValueError(
                "No cred for S3_BUCKET: {}. cred is required.".format(bucket_name)
            )

        # if this is a public bucket, Fence will not try to sign the URL
        # so it won't need to know the region.
        if cred == "*":
            continue

        if cred not in aws_creds:
            raise ValueError(
                "Credential {} for S3_BUCKET {} is not defined in AWS_CREDENTIALS".format(
                    cred, bucket_name
                )
            )

        # only require region when we're not specifying an
        # s3-compatible endpoint URL (ex: no need for region when using cleversafe)
        if not region and not bucket_details.get("endpoint_url"):
            logger.warning(
                "WARNING: no region for S3_BUCKET: {}. Providing the region will reduce"
                " response time and avoid a call to GetBucketLocation which you make lack the AWS ACLs for.".format(
                    bucket_name
                )
            )
            credential = S3IndexedFileLocation.get_credential_to_access_bucket(
                bucket_name,
                aws_creds,
                config.get("MAX_PRESIGNED_URL_TTL", 3600),
                app.boto,
            )
            if not getattr(app, "boto"):
                logger.warning(
                    "WARNING: boto not setup for app, probably b/c "
                    "nothing in AWS_CREDENTIALS. Cannot attempt to get bucket "
                    "bucket regions."
                )
                return

            region = app.boto.get_bucket_region(bucket_name, credential)
            config["S3_BUCKETS"][bucket_name]["region"] = region

    cred = config["PUSH_AUDIT_LOGS_CONFIG"].get("aws_sqs_config", {}).get("aws_cred")
    if cred and cred not in aws_creds:
        raise ValueError(
            "Credential {} for PUSH_AUDIT_LOGS_CONFIG.aws_sqs_config.aws_cred is not defined in AWS_CREDENTIALS".format(
                cred
            )
        )

    # check that all the configured buckets are in `S3_BUCKETS`
    bucket_names = config["ALLOWED_DATA_UPLOAD_BUCKETS"] or []
    if config["DATA_UPLOAD_BUCKET"]:
        bucket_names.append(config["DATA_UPLOAD_BUCKET"])
    for bucket_name in bucket_names:
        if bucket_name not in buckets:
            logger.warning(
                f"Data upload bucket '{bucket_name}' is not configured in 'S3_BUCKETS'"
            )


def app_config(
    app: FastAPI,
    root_dir=None,
    config_path=None,
    file_name=None,
):
    """
    Set up the config for the FastAPI app.
    """
    if root_dir is None:
        root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    # load the configuration file
    config.load(
        config_path=config_path,
        search_folders=CONFIG_SEARCH_FOLDERS,
        file_name=file_name,
    )

    # Attach config dict to app.state so it is accessible via request.app.state.config
    app.state.config = config._configs

    _setup_arborist_client(app)
    _setup_audit_service_client(app)
    _setup_data_endpoint_and_boto(app)
    _load_keys(app, root_dir)

    app.storage_manager = StorageManager(config["STORAGE_CREDENTIALS"], logger=logger)

    app.debug = config["DEBUG"]
    # Following will update logger level, propagate, and handlers
    get_logger(__name__, log_level="debug" if config["DEBUG"] is True else "info")

    _setup_oidc_clients(app)

    with app.app_context():
        _check_buckets_aws_creds_and_region(app)
        _check_azure_storage(app)


def _setup_data_endpoint_and_boto(app):
    if "AWS_CREDENTIALS" in config and len(config["AWS_CREDENTIALS"]) > 0:
        creds = config["AWS_CREDENTIALS"]
        buckets = config.get("S3_BUCKETS", {})
        app.boto = BotoManager(creds, buckets, logger=logger)
        app.include_router(fence.blueprints.data.router, prefix="/data")


def _load_keys(app, root_dir):
    if root_dir is None:
        root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    app.keypairs = keys.load_keypairs(os.path.join(root_dir, "keys"))

    app.jwt_public_keys = {
        config["BASE_URL"]: OrderedDict(
            [(str(keypair.kid), str(keypair.public_key)) for keypair in app.keypairs]
        )
    }


def _setup_oidc_clients(app):
    configured_idps = config.get("OPENID_CONNECT", {})

    clean_idps = [idp.lower().replace(" ", "") for idp in configured_idps]
    if len(clean_idps) != len(set(clean_idps)):
        raise ValueError(
            f"Some IDPs configured in OPENID_CONNECT are not unique once they are lowercased and spaces are removed: {clean_idps}"
        )

    for idp in set(configured_idps.keys()):
        logger.info(f"Setting up OIDC client for {idp}")
        settings = configured_idps[idp]
        if idp == "google":
            app.google_client = GoogleOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "orcid":
            app.orcid_client = OrcidOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "ras":
            app.ras_client = RASOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "synapse":
            app.synapse_client = SynapseOauth2Client(
                settings, HTTP_PROXY=config.get("HTTP_PROXY"), logger=logger
            )
        elif idp == "microsoft":
            app.microsoft_client = MicrosoftOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "okta":
            app.okta_client = OktaOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "cognito":
            app.cognito_client = CognitoOauth2Client(
                settings, HTTP_PROXY=config.get("HTTP_PROXY"), logger=logger
            )
        elif idp == "cilogon":
            app.cilogon_client = CilogonOauth2Client(
                settings,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
        elif idp == "fence":
            # https://docs.authlib.org/en/latest/client/flask.html#flask-client
            app.fence_client = OAuthClient(app)
            # https://docs.authlib.org/en/latest/client/frameworks.html
            app.fence_client.register(**settings)
        else:  # generic OIDC implementation
            if hasattr(app, "arborist"):
                app_arborist = app.arborist
            else:
                app_arborist = None
            client = Oauth2ClientBase(
                settings=settings,
                logger=logger,
                HTTP_PROXY=config.get("HTTP_PROXY"),
                idp=settings.get("name") or idp.title(),
                arborist=app_arborist,
            )
            clean_idp = idp.lower().replace(" ", "")
            setattr(app, f"{clean_idp}_client", client)


def _setup_arborist_client(app: FastAPI):
    if config.get("ARBORIST"):
        app.arborist = ArboristClient(
            arborist_base_url=config["ARBORIST"],
            timeout=config.get("ARBORIST_TIMEOUT", 30),
        )
    else:
        logger.info("Arborist not configured")
        app.arborist = None


def _setup_audit_service_client(app):
    # Initialize the client regardless of whether audit logs are enabled. This
    # allows us to call `app.audit_service_client.create_x_log()` from
    # anywhere without checking if audit logs are enabled. The client
    # checks that for us.
    service_url = config.get("AUDIT_SERVICE") or urljoin(config["BASE_URL"], "/audit")
    app.audit_service_client = AuditServiceClient(
        service_url=service_url, logger=logger
    )


@app.exception_handler(Exception)
async def handle_error(request: Request, error: Exception):
    return get_error_response(error)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup — nothing required here yet
    yield
    # shutdown — remove scoped session (replaces teardown_appcontext)
    if hasattr(app, "scoped_session"):
        try:
            app.scoped_session.remove()
        except Exception as exc:
            logger.warning(f"could not remove app.scoped_session. Error: {exc}")


# Wire the lifespan into the app that was created at module level.
# (If you use the factory pattern exclusively, pass lifespan= to FastAPI() directly.)
app.router.lifespan_context = lifespan
