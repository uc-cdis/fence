from flask import Flask, jsonify, session, redirect, request
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

app = Flask(__name__)
CORS(app=app, headers=['content-type', 'accept'], expose_headers='*')
app.register_blueprint(oauth2, url_prefix='/oauth2')
app.register_blueprint(user, url_prefix='/user')
app.register_blueprint(hmac, url_prefix='/hmac')
app.register_blueprint(credentials, url_prefix='/credentials')
app.register_blueprint(admin, url_prefix='/admin')
app.register_blueprint(login, url_prefix='/login')
init_oauth(app)


def app_config(app, settings='fence.settings'):
    """
    Set up the config for the Flask app.
    """
    app.config.from_object(settings)


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
    app_config(app, settings)
    app_sessions(app)


def generate_csrf_token():
    """
    Generate a token used for CSRF protection.

    If the session does not currently have such a CSRF token, assign it one
    from a random string. Then return the session's CSRF token.
    """
    if '_csrf_token' not in session:
        session['_csrf_token'] = random_str(20)
    return session['_csrf_token']


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
    return jsonify(endpoints)


@app.route('/logout')
def logout_endpoint():
    root = app.config.get('APPLICATION_ROOT', '')
    next_url = app.config.get('HOSTNAME', '') + request.args.get('next', root)
    return redirect(logout(next_url=next_url))


@app.route('/keys')
def public_keys():
    # TODO
    pass


@app.errorhandler(Exception)
def user_error(error):
    """
    Register an error handler for general exceptions.
    """
    if isinstance(error, APIError):
        if hasattr(error, 'json') and error.json:
            return jsonify(**error.json), error.code
        else:
            return jsonify(message=error.message), error.code
    else:
        app.logger.exception("Catch exception")
        return jsonify(error=error.message), 500


@app.before_request
def check_csrf():
    if 'Authorization' in request.headers or not session.get('username'):
        return
    if not app.config.get('ENABLE_CSRF_PROTECTION', True):
        return
    # cookie based authentication
    if request.method != 'GET':
        csrf_cookie = request.headers.get('x-csrf-token')
        csrf_header = request.cookies.get('csrftoken')
        if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
            raise UserError("CSRF verification failed. Request aborted")


@app.after_request
def set_csrf(response):
    """
    Create a cookie for CSRF protection if one does not yet exist.
    """
    if not request.cookies.get('csrftoken'):
        secure = app.config.get('SESSION_COOKIE_SECURE', True)
        response.set_cookie('csrftoken', random_str(40), secure=secure)
    return response
