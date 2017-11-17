from collections import OrderedDict
import os

import flask
from flask.ext.cors import CORS
from flask_postgres_session import PostgresSessionInterface
from flask_sqlalchemy_session import flask_scoped_session
from userdatamodel.driver import SQLAlchemyDriver

from .admin import blueprint as admin
from .auth import logout
from .errors import APIError
from .errors import UserError
from .hmac_auth import blueprint as hmac
from .login import blueprint as login
from .models import UserSession
from .oauth2 import init_oauth
from .oauth2 import blueprint as oauth2
from .resources.aws.boto_manager import BotoManager
from .resources.openid.google_oauth2 import Oauth2Client
from .storage_creds import blueprint as credentials
from .user import blueprint as user
from .utils import random_str

app = flask.Flask(__name__)
CORS(app=app, headers=['content-type', 'accept'], expose_headers='*')
app.register_blueprint(oauth2, url_prefix='/oauth2')
app.register_blueprint(user, url_prefix='/user')
app.register_blueprint(hmac, url_prefix='/hmac')
app.register_blueprint(credentials, url_prefix='/credentials')
app.register_blueprint(admin, url_prefix='/admin')
app.register_blueprint(login, url_prefix='/login')


def app_config(app, settings='fence.settings'):
    """
    Set up the config for the Flask app.
    """
    app.config.from_object(settings)
    keys = []
    root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    for kid, (public, private) in app.config['JWT_KEYPAIR_FILES'].iteritems():
        public_filepath = os.path.join(root_dir, public)
        private_filepath = os.path.join(root_dir, private)
        with open(public_filepath, 'r') as f:
            public_key = f.read()
        with open(private_filepath, 'r') as f:
            private_key = f.read()
        entry = (kid, (public_key, private_key))
        keys.append(entry)
    app.keys = OrderedDict(keys)


app_config(app)
init_oauth(app)


def app_sessions(app):
    app.url_map.strict_slashes = False
    app.db = SQLAlchemyDriver(app.config['DB'])
    session = flask_scoped_session(app.db.Session, app)  # noqa
    app.boto = BotoManager(app.config['AWS'])
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    if ('OPENID_CONNECT' in app.config
        and 'google' in app.config['OPENID_CONNECT']):
        app.google_client = Oauth2Client(
            app.config['OPENID_CONNECT']['google'],
            HTTP_PROXY=app.config.get('HTTP_PROXY'),
            logger=app.logger
        )
    app.session_interface = PostgresSessionInterface(UserSession)  # noqa


def app_init(app, settings='fence.settings'):
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


@app.route('/keys')
def public_keys():
    """
    Return the public keys which can be used to verify JWTs signed by fence.
    """
    return flask.jsonify({
        'keys': [
            (kid, public_key)
            for (kid, (public_key, _)) in app.keys.iteritems()
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
