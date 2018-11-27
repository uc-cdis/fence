from collections import OrderedDict
import os

from authutils.oauth2.client import OAuthClient
import flask
from flask_cors import CORS
from flask_sqlalchemy_session import flask_scoped_session, current_session
from cdislogging import get_stream_handler
from userdatamodel.driver import SQLAlchemyDriver

from fence.auth import logout, build_redirect_url
from fence.errors import UserError
from fence.jwt import keys
from fence.models import migrate
from fence.oidc.jwt_generator import generate_token
from fence.oidc.client import query_client
from fence.oidc.server import server
from fence.rbac.client import ArboristClient
from fence.resources.aws.boto_manager import BotoManager
from fence.resources.openid.google_oauth2 import Oauth2Client as GoogleClient
from fence.resources.storage import StorageManager
from fence.resources.user.user_session import UserSessionInterface
from fence.error_handler import get_error_response
from fence.utils import random_str
from fence.config import config
import fence.blueprints.admin
import fence.blueprints.data
import fence.blueprints.login
import fence.blueprints.oauth2
import fence.blueprints.rbac
import fence.blueprints.misc
import fence.blueprints.storage_creds
import fence.blueprints.user
import fence.blueprints.well_known
import fence.blueprints.link
import fence.blueprints.google

from cdislogging import get_logger

logger = get_logger(__name__)

app = flask.Flask(__name__)
CORS(app=app, headers=["content-type", "accept"], expose_headers="*")


def app_init(
    app,
    settings="fence.settings",
    root_dir=None,
    config_path=None,
    config_file_name=None,
):
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
    migrate(app.db)
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

    if config.get("ARBORIST"):
        app.register_blueprint(fence.blueprints.rbac.blueprint, url_prefix="/rbac")

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
        if request_next.startswith("https") or request_next.startswith("http"):
            next_url = request_next
        else:
            next_url = build_redirect_url(config.get("ROOT_URL", ""), request_next)
        return logout(next_url=next_url)

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
    config.load(config_path, file_name)

    # load all config back into flask app config for now, we should PREFER getting config
    # directly from the fence config singleton in the code though.
    app.config.update(**config._configs)

    _setup_data_endpoint_and_boto(app)
    _load_keys(app, root_dir)
    _set_authlib_cfgs(app)

    app.storage_manager = StorageManager(
        config["STORAGE_CREDENTIALS"], logger=app.logger
    )

    _setup_oidc_clients(app)
    _setup_arborist_client(app)


def _setup_data_endpoint_and_boto(app):
    if "AWS_CREDENTIALS" in config and len(config["AWS_CREDENTIALS"]) > 0:
        value = config["AWS_CREDENTIALS"].values()[0]
        app.boto = BotoManager(value, logger=app.logger)
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
    enabled_idp_ids = config["ENABLED_IDENTITY_PROVIDERS"]["providers"].keys()

    # Add OIDC client for Google if configured.
    configured_google = (
        "OPENID_CONNECT" in config
        and "google" in config["OPENID_CONNECT"]
        and "google" in enabled_idp_ids
    )
    if configured_google:
        app.google_client = GoogleClient(
            config["OPENID_CONNECT"]["google"],
            HTTP_PROXY=config.get("HTTP_PROXY"),
            logger=app.logger,
        )

    # Add OIDC client for multi-tenant fence if configured.
    configured_fence = (
        "OPENID_CONNECT" in config
        and "fence" in config["OPENID_CONNECT"]
        and "fence" in enabled_idp_ids
    )
    if configured_fence:
        app.fence_client = OAuthClient(**config["OPENID_CONNECT"]["fence"])


def _setup_arborist_client(app):
    if config.get("ARBORIST"):
        app.arborist = ArboristClient(arborist_base_url=config["ARBORIST"])


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
        flask.current_app.logger.debug("HTTP REFERER " + str(referer))
        if not all([csrf_cookie, csrf_header, csrf_cookie == csrf_header, referer]):
            raise UserError("CSRF verification failed. Request aborted")


@app.after_request
def set_csrf(response):
    """
    Create a cookie for CSRF protection if one does not yet exist.
    """
    if not flask.request.cookies.get("csrftoken"):
        secure = config.get("SESSION_COOKIE_SECURE", True)
        response.set_cookie("csrftoken", random_str(40), secure=secure)

    if flask.request.method in ["POST", "PUT", "DELETE"]:
        current_session.commit()
    return response
