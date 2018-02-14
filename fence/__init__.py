from collections import OrderedDict
import os

from authlib.specs.rfc6749.errors import OAuth2Error
from authutils.oauth2.client import OAuthClient
import flask
from flask.ext.cors import CORS
from flask_sqlalchemy_session import flask_scoped_session
from userdatamodel.driver import SQLAlchemyDriver

from fence.auth import logout, build_redirect_url
from fence.errors import APIError, UserError
from fence.jwt import keys
from fence.models import migrate
from fence.oidc.server import server
from fence.resources.aws.boto_manager import BotoManager
from fence.resources.openid.google_oauth2 import Oauth2Client as GoogleClient
from fence.resources.storage import StorageManager
from fence.resources.user.user_session import UserSessionInterface
from fence.utils import random_str
import fence.blueprints.admin
import fence.blueprints.data
import fence.blueprints.login
import fence.blueprints.oauth2
import fence.blueprints.storage_creds
import fence.blueprints.user
import fence.blueprints.well_known
import fence.client


app = flask.Flask(__name__)
CORS(app=app, headers=['content-type', 'accept'], expose_headers='*')
app.register_blueprint(fence.blueprints.oauth2.blueprint, url_prefix='/oauth2')
app.register_blueprint(fence.blueprints.user.blueprint, url_prefix='/user')
app.register_blueprint(fence.blueprints.storage_creds.blueprint, url_prefix='/credentials')
app.register_blueprint(fence.blueprints.admin.blueprint, url_prefix='/admin')
app.register_blueprint(fence.blueprints.login.blueprint, url_prefix='/login')
app.register_blueprint(fence.blueprints.well_known.blueprint, url_prefix='/.well-known')


def app_config(app, settings='fence.settings', root_dir=None):
    """
    Set up the config for the Flask app.
    """
    app.config.from_object(settings)
    if 'BASE_URL' not in app.config:
        base_url = app.config['HOSTNAME']
        if not base_url.startswith('http'):
            base_url = 'https://' + base_url
        app.config['BASE_URL'] = base_url
    app.keypairs = []
    if root_dir is None:
        root_dir = os.path.dirname(
                os.path.dirname(os.path.realpath(__file__)))
    if 'AWS_CREDENTIALS' in app.config and len(app.config['AWS_CREDENTIALS']) > 0:
        value = app.config['AWS_CREDENTIALS'].values()[0]
        app.boto = BotoManager(value)
        app.register_blueprint(
            fence.blueprints.data.blueprint, url_prefix='/data'
        )
    for kid, (public, private) in app.config['JWT_KEYPAIR_FILES'].iteritems():
        public_filepath = os.path.join(root_dir, public)
        private_filepath = os.path.join(root_dir, private)
        with open(public_filepath, 'r') as f:
            public_key = f.read()
        with open(private_filepath, 'r') as f:
            private_key = f.read()
        app.keypairs.append(keys.Keypair(
            kid=kid, public_key=public_key, private_key=private_key
        ))
    # The fence app implements ``app.jwt_public_keys`` in the same fashion as
    # the clients, so that fence can also call the validation functions in
    # ``cdispyutils``.
    app.jwt_public_keys = OrderedDict([
        (str(keypair.kid), str(keypair.public_key))
        for keypair in app.keypairs
    ])


def app_sessions(app):
    app.url_map.strict_slashes = False
    app.db = SQLAlchemyDriver(app.config['DB'])
    migrate(app.db)
    session = flask_scoped_session(app.db.Session, app)  # noqa
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.storage_manager = StorageManager(
        app.config['STORAGE_CREDENTIALS'],
        logger=app.logger
    )
    # Add OIDC client for Google if configured.
    configured_google = (
        'OPENID_CONNECT' in app.config
        and 'google' in app.config['OPENID_CONNECT']
    )
    if configured_google:
        app.google_client = GoogleClient(
            app.config['OPENID_CONNECT']['google'],
            HTTP_PROXY=app.config.get('HTTP_PROXY'),
            logger=app.logger
        )
    # Add OIDC client for multi-tenant fence if configured.
    configured_fence = (
        'OPENID_CONNECT' in app.config
        and 'fence' in app.config['OPENID_CONNECT']
        and 'fence' in fence.settings.ENABLED_IDENTITY_PROVIDERS
    )
    if configured_fence:
        app.fence_client = OAuthClient(**app.config['OPENID_CONNECT']['fence'])
        # TODO

    app.session_interface = UserSessionInterface()


def app_init(app, settings='fence.settings', root_dir=None):
    app_config(app, settings=settings, root_dir=root_dir)
    server.init_app(app)
    app_sessions(app)


def generate_csrf_token():
    """
    Generate a token used for CSRF protection.

    If the session does not currently have such a CSRF token, assign it one
    from a random string. Then return the session's CSRF token.
    """
    if '_csrf_token' not in flask.session:
        flask.session['_csrf_token'] = random_str(20)
    return flask.session['_csrf_token']


@app.route('/')
def root():
    """
    Register the root URL.
    """
    endpoints = {
        'oauth2 endpoint': '/oauth2',
        'user endpoint': '/user',
        'keypair endpoint': '/credentials'
    }
    return flask.jsonify(endpoints)


@app.route('/logout')
def logout_endpoint():
    root = app.config.get('APPLICATION_ROOT', '')
    next_url = build_redirect_url(app.config.get('BASE_URL', ''), flask.request.args.get('next', root))
    return flask.redirect(logout(next_url=next_url))


@app.route('/jwt/keys')
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
    return flask.jsonify({
        'keys': [
            (keypair.kid, keypair.public_key)
            for keypair in app.keypairs
        ]
    })


@app.errorhandler(Exception)
def user_error(error):
    """
    Register an error handler for general exceptions.
    """
    if isinstance(error, APIError):
        if hasattr(error, 'json') and error.json:
            return flask.jsonify(**error.json), error.code
        else:
            return flask.jsonify(message=error.message), error.code
    elif isinstance(error, OAuth2Error):
        return flask.jsonify(error.get_body()), error.status_code
    else:
        app.logger.exception("Catch exception")
        return flask.jsonify(error=error.message), 500


@app.before_request
def check_csrf():
    has_auth = 'Authorization' in flask.request.headers
    no_username = not flask.session.get('username')
    if has_auth or no_username:
        return
    if not app.config.get('ENABLE_CSRF_PROTECTION', True):
        return
    # cookie based authentication
    if flask.request.method != 'GET':
        csrf_cookie = flask.request.headers.get('x-csrf-token')
        csrf_header = flask.request.cookies.get('csrftoken')
        if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
            raise UserError("CSRF verification failed. Request aborted")


@app.after_request
def set_csrf(response):
    """
    Create a cookie for CSRF protection if one does not yet exist.
    """
    if not flask.request.cookies.get('csrftoken'):
        secure = app.config.get('SESSION_COOKIE_SECURE', True)
        response.set_cookie('csrftoken', random_str(40), secure=secure)
    return response
