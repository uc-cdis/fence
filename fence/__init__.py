from collections import OrderedDict
import os

import flask
from flask.ext.cors import CORS
from flask_postgres_session import PostgresSessionInterface
from flask_sqlalchemy_session import flask_scoped_session

from .auth import logout
from .blueprints.admin import blueprint as admin
from .blueprints.login import blueprint as login
from .blueprints.data import blueprint as data
from .blueprints.oauth2 import blueprint as oauth2
from .blueprints.storage_creds import blueprint as credentials
from .blueprints.oauth2 import init_oauth
from .resources.storage import StorageManager
from .blueprints.user import blueprint as user
from .errors import APIError, UserError
from .data_model.models import UserSession, migrate
from .jwt import keys
from .resources.aws.boto_manager import BotoManager
from .resources.openid.google_oauth2 import Oauth2Client
from .utils import random_str

from userdatamodel.driver import SQLAlchemyDriver

app = flask.Flask(__name__)
CORS(app=app, headers=['content-type', 'accept'], expose_headers='*')
app.register_blueprint(admin, url_prefix='/admin')
app.register_blueprint(credentials, url_prefix='/credentials')
app.register_blueprint(login, url_prefix='/login')
app.register_blueprint(oauth2, url_prefix='/oauth2')
app.register_blueprint(user, url_prefix='/user')
app.register_blueprint(data, url_prefix='/data')


def app_config(app, settings='fence.settings', root_dir=None):
    """
    Set up the config for the Flask app.
    """
    app.config.from_object(settings)
    app.keypairs = []
    if root_dir is None:
        root_dir = os.path.dirname(
                os.path.dirname(os.path.realpath(__file__)))
    app.boto = BotoManager(app.config['AWS'])
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
        (keypair.kid, keypair.public_key)
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
    if ('OPENID_CONNECT' in app.config
        and 'google' in app.config['OPENID_CONNECT']):
        app.google_client = Oauth2Client(
            app.config['OPENID_CONNECT']['google'],
            HTTP_PROXY=app.config.get('HTTP_PROXY'),
            logger=app.logger
        )
    app.session_interface = PostgresSessionInterface(UserSession)  # noqa


def app_init(app, settings='fence.settings', root_dir=None):
    app_config(app, settings=settings, root_dir=root_dir)
    init_oauth(app)
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
    next_url = (
        app.config.get('HOSTNAME', '')
        + flask.request.args.get('next', root)
    )
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
