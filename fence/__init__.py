from collections import OrderedDict
import os

from authutils.oauth2.client import OAuthClient
import flask
from flask_cors import CORS
from flask_sqlalchemy_session import flask_scoped_session, current_session
from urllib.parse import urljoin
from userdatamodel.driver import SQLAlchemyDriver

from fence.auth import logout, build_redirect_url
from fence.blueprints.data.indexd import S3IndexedFileLocation
from fence.blueprints.login.utils import allowed_login_redirects, domain
from fence.errors import UserError
from fence.jwt import keys
from fence.models import migrate
from fence.oidc.client import query_client
from fence.oidc.server import server
from fence.resources.audit_service_client import AuditServiceClient
from fence.resources.aws.boto_manager import BotoManager
from fence.resources.openid.cognito_oauth2 import CognitoOauth2Client as CognitoClient
from fence.resources.openid.google_oauth2 import GoogleOauth2Client as GoogleClient
from fence.resources.openid.microsoft_oauth2 import (
    MicrosoftOauth2Client as MicrosoftClient,
)
from fence.resources.openid.okta_oauth2 import OktaOauth2Client as OktaClient
from fence.resources.openid.orcid_oauth2 import OrcidOauth2Client as ORCIDClient
from fence.resources.openid.synapse_oauth2 import SynapseOauth2Client as SynapseClient
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient
from fence.resources.storage import StorageManager
from fence.resources.user.user_session import UserSessionInterface
from fence.error_handler import get_error_response
from fence.utils import random_str
from fence.config import config
from fence.settings import CONFIG_SEARCH_FOLDERS
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

from cdislogging import get_logger

from cdispyutils.config import get_value

from gen3authz.client.arborist.client import ArboristClient

# Can't read config yet. Just set to debug for now, else no handlers.
# Later, in app_config(), will actually set level based on config
logger = get_logger(__name__, log_level="debug")

app = flask.Flask(__name__)
CORS(app=app, headers=["content-type", "accept"], expose_headers="*")


def warn_about_logger():
    raise Exception(
        "Flask 0.12 will remove and replace all of our log handlers if you call "
        "app.logger anywhere. Use get_logger from cdislogging instead."
    )


def app_init(
    app,
    settings="fence.settings",
    root_dir=None,
    config_path=None,
    config_file_name=None,
):
    app.__dict__["logger"] = warn_about_logger

    app_config(
        app,
        settings=settings,
        root_dir=root_dir,
        config_path=config_path,
        file_name=config_file_name,
    )
    app_sessions(app)
    app_register_blueprints(app)
    server.init_app(app, query_client=query_client)


def app_sessions(app):
    app.url_map.strict_slashes = False
    app.db = SQLAlchemyDriver(config["DB"])

    # TODO: we will make a more robust migration system external from the application
    #       initialization soon
    if config["ENABLE_DB_MIGRATION"]:
        logger.info("Running database migration...")
        migrate(app.db)
        logger.info("Done running database migration.")
    else:
        logger.info("NOT running database migration.")

    session = flask_scoped_session(app.db.Session, app)  # noqa
    app.session_interface = UserSessionInterface()


def app_register_blueprints(app):
    app.register_blueprint(fence.blueprints.oauth2.blueprint, url_prefix="/oauth2")
    app.register_blueprint(fence.blueprints.user.blueprint, url_prefix="/user")

    creds_blueprint = fence.blueprints.storage_creds.make_creds_blueprint()
    app.register_blueprint(creds_blueprint, url_prefix="/credentials")

    app.register_blueprint(fence.blueprints.admin.blueprint, url_prefix="/admin")
    app.register_blueprint(
        fence.blueprints.well_known.blueprint, url_prefix="/.well-known"
    )

    login_blueprint = fence.blueprints.login.make_login_blueprint(app)
    app.register_blueprint(login_blueprint, url_prefix="/login")

    link_blueprint = fence.blueprints.link.make_link_blueprint()
    app.register_blueprint(link_blueprint, url_prefix="/link")

    google_blueprint = fence.blueprints.google.make_google_blueprint()
    app.register_blueprint(google_blueprint, url_prefix="/google")

    app.register_blueprint(
        fence.blueprints.privacy.blueprint, url_prefix="/privacy-policy"
    )

    fence.blueprints.misc.register_misc(app)

    @app.route("/")
    def root():
        """
        Register the root URL.
        """
        endpoints = {
            "oauth2 endpoint": "/oauth2",
            "user endpoint": "/user",
            "keypair endpoint": "/credentials",
        }
        return flask.jsonify(endpoints)

    @app.route("/logout")
    def logout_endpoint():
        root = config.get("BASE_URL", "")
        request_next = flask.request.args.get("next", root)
        force_era_global_logout = (
            flask.request.args.get("force_era_global_logout") == "true"
        )
        if request_next.startswith("https") or request_next.startswith("http"):
            next_url = request_next
        else:
            next_url = build_redirect_url(config.get("ROOT_URL", ""), request_next)
        if domain(next_url) not in allowed_login_redirects():
            raise UserError("invalid logout redirect URL: {}".format(next_url))
        return logout(
            next_url=next_url, force_era_global_logout=force_era_global_logout
        )

    @app.route("/jwt/keys")
    def public_keys():
        """
        Return the public keys which can be used to verify JWTs signed by fence.

        The return value should look like this:
            {
                "keys": [
                    {
                        "key-01": " ... [public key here] ... "
                    }
                ]
            }
        """
        return flask.jsonify(
            {"keys": [(keypair.kid, keypair.public_key) for keypair in app.keypairs]}
        )


def _check_s3_buckets(app):
    """
    Function to ensure that all s3_buckets have a valid credential.
    Additionally, if there is no region it will produce a warning then try to fetch and cache the region.
    """
    buckets = config.get("S3_BUCKETS") or {}
    aws_creds = config.get("AWS_CREDENTIALS") or {}

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


def app_config(
    app, settings="fence.settings", root_dir=None, config_path=None, file_name=None
):
    """
    Set up the config for the Flask app.
    """
    if root_dir is None:
        root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    logger.info("Loading settings...")
    # not using app.config.from_object because we don't want all the extra flask cfg
    # vars inside our singleton when we pass these through in the next step
    settings_cfg = flask.Config(app.config.root_path)
    settings_cfg.from_object(settings)

    # dump the settings into the config singleton before loading a configuration file
    config.update(dict(settings_cfg))

    # load the configuration file, this overwrites anything from settings/local_settings
    config.load(
        config_path=config_path,
        search_folders=CONFIG_SEARCH_FOLDERS,
        file_name=file_name,
    )

    # load all config back into flask app config for now, we should PREFER getting config
    # directly from the fence config singleton in the code though.
    app.config.update(**config._configs)

    _setup_arborist_client(app)
    _setup_audit_service_client(app)
    _setup_data_endpoint_and_boto(app)
    _load_keys(app, root_dir)
    _set_authlib_cfgs(app)

    app.storage_manager = StorageManager(config["STORAGE_CREDENTIALS"], logger=logger)

    app.debug = config["DEBUG"]
    # Following will update logger level, propagate, and handlers
    get_logger(__name__, log_level="debug" if config["DEBUG"] == True else "info")

    _setup_oidc_clients(app)

    _check_s3_buckets(app)


def _setup_data_endpoint_and_boto(app):
    if "AWS_CREDENTIALS" in config and len(config["AWS_CREDENTIALS"]) > 0:
        value = list(config["AWS_CREDENTIALS"].values())[0]
        app.boto = BotoManager(value, logger=logger)
        app.register_blueprint(fence.blueprints.data.blueprint, url_prefix="/data")


def _load_keys(app, root_dir):
    if root_dir is None:
        root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    app.keypairs = keys.load_keypairs(os.path.join(root_dir, "keys"))

    app.jwt_public_keys = {
        config["BASE_URL"]: OrderedDict(
            [(str(keypair.kid), str(keypair.public_key)) for keypair in app.keypairs]
        )
    }


def _set_authlib_cfgs(app):
    # authlib OIDC settings
    # key will need to be added
    settings = {"OAUTH2_JWT_KEY": keys.default_private_key(app)}
    app.config.update(settings)
    config.update(settings)

    # only add the following if not already provided
    config.setdefault("OAUTH2_JWT_ENABLED", True)
    config.setdefault("OAUTH2_JWT_ALG", "RS256")
    config.setdefault("OAUTH2_JWT_ISS", app.config["BASE_URL"])
    config.setdefault("OAUTH2_PROVIDER_ERROR_URI", "/api/oauth2/errors")
    app.config.setdefault("OAUTH2_JWT_ENABLED", True)
    app.config.setdefault("OAUTH2_JWT_ALG", "RS256")
    app.config.setdefault("OAUTH2_JWT_ISS", app.config["BASE_URL"])
    app.config.setdefault("OAUTH2_PROVIDER_ERROR_URI", "/api/oauth2/errors")


def _setup_oidc_clients(app):
    oidc = config.get("OPENID_CONNECT", {})

    # Add OIDC client for Google if configured.
    if "google" in oidc:
        app.google_client = GoogleClient(
            config["OPENID_CONNECT"]["google"],
            HTTP_PROXY=config.get("HTTP_PROXY"),
            logger=logger,
        )

    # Add OIDC client for ORCID if configured.
    if "orcid" in oidc:
        app.orcid_client = ORCIDClient(
            config["OPENID_CONNECT"]["orcid"],
            HTTP_PROXY=config.get("HTTP_PROXY"),
            logger=logger,
        )

    # Add OIDC client for RAS if configured.
    if "ras" in oidc:
        app.ras_client = RASClient(
            oidc["ras"],
            HTTP_PROXY=config.get("HTTP_PROXY"),
            logger=logger,
        )

    # Add OIDC client for Synapse if configured.
    if "synapse" in oidc:
        app.synapse_client = SynapseClient(
            oidc["synapse"], HTTP_PROXY=config.get("HTTP_PROXY"), logger=logger
        )

    # Add OIDC client for Microsoft if configured.
    if "microsoft" in oidc:
        app.microsoft_client = MicrosoftClient(
            config["OPENID_CONNECT"]["microsoft"],
            HTTP_PROXY=config.get("HTTP_PROXY"),
            logger=logger,
        )

    # Add OIDC client for Okta if configured
    if "okta" in oidc:
        app.okta_client = OktaClient(
            config["OPENID_CONNECT"]["okta"],
            HTTP_PROXY=config.get("HTTP_PROXY"),
            logger=logger,
        )

    # Add OIDC client for Amazon Cognito if configured.
    if "cognito" in oidc:
        app.cognito_client = CognitoClient(
            oidc["cognito"], HTTP_PROXY=config.get("HTTP_PROXY"), logger=logger
        )

    # Add OIDC client for multi-tenant fence if configured.
    if "fence" in oidc:
        app.fence_client = OAuthClient(**config["OPENID_CONNECT"]["fence"])


def _setup_arborist_client(app):
    if app.config.get("ARBORIST"):
        app.arborist = ArboristClient(arborist_base_url=config["ARBORIST"])


def _setup_audit_service_client(app):
    # Initialize the client regardless of whether audit logs are enabled. This
    # allows us to call `app.audit_service_client.create_x_log()` from
    # anywhere without checking if audit logs are enabled. The client
    # checks that for us.
    service_url = app.config.get("AUDIT_SERVICE") or urljoin(
        app.config["BASE_URL"], "/audit"
    )
    app.audit_service_client = AuditServiceClient(
        service_url=service_url, logger=logger
    )


@app.errorhandler(Exception)
def handle_error(error):
    """
    Register an error handler for general exceptions.
    """
    return get_error_response(error)


@app.before_request
def check_csrf():
    has_auth = "Authorization" in flask.request.headers
    no_username = not flask.session.get("username")
    if has_auth or no_username:
        return
    if not config.get("ENABLE_CSRF_PROTECTION", True):
        return
    # cookie based authentication
    if flask.request.method != "GET":
        csrf_header = flask.request.headers.get("x-csrf-token")
        csrf_cookie = flask.request.cookies.get("csrftoken")
        referer = flask.request.headers.get("referer")
        logger.debug("HTTP REFERER " + str(referer))
        if not all([csrf_cookie, csrf_header, csrf_cookie == csrf_header, referer]):
            raise UserError("CSRF verification failed. Request aborted")


@app.after_request
def set_csrf(response):
    """
    Create a cookie for CSRF protection if one does not yet exist
    """
    if not flask.request.cookies.get("csrftoken"):
        secure = config.get("SESSION_COOKIE_SECURE", True)
        response.set_cookie("csrftoken", random_str(40), secure=secure, httponly=True)

    if flask.request.method in ["POST", "PUT", "DELETE"]:
        current_session.commit()
    return response
