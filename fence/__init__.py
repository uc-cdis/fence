from collections import OrderedDict
import os

from authutils.oauth2.client import OAuthClient
import cirrus
import flask
from flask_cors import CORS
from flask_sqlalchemy_session import flask_scoped_session, current_session
import urlparse
from userdatamodel.driver import SQLAlchemyDriver

from fence.auth import logout, build_redirect_url
from fence.errors import UserError
from fence.jwt import keys
from fence.models import migrate
from fence.oidc.server import server
from fence.rbac.client import ArboristClient
from fence.resources.aws.boto_manager import BotoManager
from fence.resources.openid.google_oauth2 import Oauth2Client as GoogleClient
from fence.resources.storage import StorageManager
from fence.resources.user.user_session import UserSessionInterface
from fence.error_handler import get_error_response
from fence.utils import random_str
import fence.blueprints.admin
import fence.blueprints.data
import fence.blueprints.login
import fence.blueprints.oauth2
import fence.blueprints.rbac
import fence.blueprints.storage_creds
import fence.blueprints.user
import fence.blueprints.well_known
import fence.blueprints.link
import fence.blueprints.google
import fence.client


app = flask.Flask(__name__)
CORS(app=app, headers=['content-type', 'accept'], expose_headers='*')


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
    if 'ROOT_URL' not in app.config:
        url = urlparse.urlparse(app.config['BASE_URL'])
        app.config['ROOT_URL'] = '{}://{}'.format(url.scheme, url.netloc)

    if root_dir is None:
        root_dir = os.path.dirname(
                os.path.dirname(os.path.realpath(__file__)))
    if 'AWS_CREDENTIALS' in app.config and len(app.config['AWS_CREDENTIALS']) > 0:
        value = app.config['AWS_CREDENTIALS'].values()[0]
        app.boto = BotoManager(value, logger=app.logger)
        app.register_blueprint(
            fence.blueprints.data.blueprint, url_prefix='/data'
        )

    app.keypairs = keys.load_keypairs(os.path.join(root_dir, 'keys'))

    app.jwt_public_keys = {
        app.config['BASE_URL']: OrderedDict([
            (str(keypair.kid), str(keypair.public_key))
            for keypair in app.keypairs
        ])
    }

    cirrus.config.config.update(**app.config.get('CIRRUS_CFG', {}))


def app_register_blueprints(app):
    app.register_blueprint(fence.blueprints.oauth2.blueprint, url_prefix='/oauth2')
    app.register_blueprint(fence.blueprints.user.blueprint, url_prefix='/user')

    creds_blueprint = fence.blueprints.storage_creds.make_creds_blueprint()
    app.register_blueprint(creds_blueprint, url_prefix='/credentials')

    app.register_blueprint(fence.blueprints.admin.blueprint, url_prefix='/admin')
    app.register_blueprint(fence.blueprints.well_known.blueprint, url_prefix='/.well-known')

    login_blueprint = fence.blueprints.login.make_login_blueprint(app)
    app.register_blueprint(login_blueprint, url_prefix='/login')

    link_blueprint = fence.blueprints.link.make_link_blueprint()
    app.register_blueprint(link_blueprint, url_prefix='/link')

    google_blueprint = fence.blueprints.google.make_google_blueprint()
    app.register_blueprint(google_blueprint, url_prefix='/google')

    if app.config.get('ARBORIST'):
        app.register_blueprint(
            fence.blueprints.rbac.blueprint,
            url_prefix='/rbac'
        )

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
        root = app.config.get('BASE_URL', '')
        request_next = flask.request.args.get('next', root)
        if request_next.startswith('https') or request_next.startswith('http'):
            next_url = request_next
        else:
            next_url = build_redirect_url(app.config.get('ROOT_URL', ''), request_next)
        return logout(next_url=next_url)

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


def app_sessions(app):
    app.url_map.strict_slashes = False
    app.db = SQLAlchemyDriver(app.config['DB'])
    migrate(app.db)
    session = flask_scoped_session(app.db.Session, app)  # noqa
    app.storage_manager = StorageManager(
        app.config['STORAGE_CREDENTIALS'],
        logger=app.logger
    )
    enabled_idp_ids = (
        app.config['ENABLED_IDENTITY_PROVIDERS']['providers'].keys()
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
        and 'fence' in enabled_idp_ids
    )
    if configured_fence:
        app.fence_client = OAuthClient(**app.config['OPENID_CONNECT']['fence'])
    app.session_interface = UserSessionInterface()
    if app.config.get('ARBORIST'):
        app.arborist = ArboristClient(
            arborist_base_url=app.config['ARBORIST']['base_url']
        )


def app_init(app, settings='fence.settings', root_dir=None):
    app_config(app, settings=settings, root_dir=root_dir)
    app_sessions(app)
    app_register_blueprints(app)
    server.init_app(app)


@app.errorhandler(Exception)
def handle_error(error):
    """
    Register an error handler for general exceptions.
    """
    return get_error_response(error)


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
        csrf_header = flask.request.headers.get('x-csrf-token')
        csrf_cookie = flask.request.cookies.get('csrftoken')
        referer = flask.request.headers.get('referer')
        flask.current_app.logger.debug('HTTP REFERER ' + str(referer))
        if not all([csrf_cookie, csrf_header, csrf_cookie == csrf_header, referer]):
            raise UserError("CSRF verification failed. Request aborted")


@app.after_request
def set_csrf(response):
    """
    Create a cookie for CSRF protection if one does not yet exist.
    """
    if not flask.request.cookies.get('csrftoken'):
        secure = app.config.get('SESSION_COOKIE_SECURE', True)
        response.set_cookie('csrftoken', random_str(40), secure=secure)

    if flask.request.method in ['POST', 'PUT', 'DELETE']:
        current_session.commit()
    return response
