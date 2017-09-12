from flask import Flask, jsonify, session, redirect, request
from flask.ext.cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy_session import flask_scoped_session
from userdatamodel.driver import SQLAlchemyDriver

from .errors import APIError
from .exchange_jwt import hmac_to_jwt


app = Flask(__name__)
CORS(app=app, headers=['content-type', 'accept'], expose_headers='*')


def app_config(app, settings='fence.settings'):
    """
    Set up the config for the Flask app.
    """
    app.config.from_object(settings)


def app_sessions(app):
    app.url_map.strict_slashes = False
    app.db = SQLAlchemyDriver(app.config['DB'])
    session = flask_scoped_session(app.db.Session, app)  # noqa

def init_jwt(app):
    jwt = JWTManager(app)

def app_init(app, settings='fence.settings'):
    app_config(app, settings)
    app_sessions(app)
    init_jwt(app)


@app.route('/<service>')
def root(service):
    return hmac_to_jwt(request, service)

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
