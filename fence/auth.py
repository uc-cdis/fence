from functools import wraps

from cdispyutils import auth
import flask
from flask_sqlalchemy_session import current_session

from fence.errors import Unauthorized, InternalError
from fence.data_model.models import User, IdentityProvider
from flask import current_app as capp


def login_user(request, username, provider):
    user = current_session.query(
        User).filter(User.username == username).first()
    if not user:
        user = User(username=username)
        idp = (
            current_session.query(IdentityProvider)
            .filter(IdentityProvider.name == provider).first()
        )
        if not idp:
            raise InternalError("{} provider not setup".format(provider))
        user.identity_provider = idp
        current_session.add(user)
        current_session.commit()
    flask.g.user = user
    flask.g.scopes = ["_all"]
    flask.g.token = None


def logout(next_url=None):
    # Call get_current_user (but ignore the result) just to check that either
    # the user is logged in or that authorization is mocked.
    get_current_user()
    if flask.session['provider'] == IdentityProvider.itrust:
        next_url = flask.current_app.config['ITRUST_GLOBAL_LOGOUT'] + next_url
    flask.session.clear()
    return next_url


def check_scope(scope):
    def wrapper(f):
        @wraps(f)
        def check_scope_and_call(*args, **kwargs):
            if '_all' in flask.g.scopes or scope in flask.g.scopes:
                return f(*args, **kwargs)
            else:
                raise Unauthorized(
                    "Requested scope {} can't access this endpoint"
                    .format(scope))
        return check_scope_and_call
    return wrapper


def login_required(scope=None):
    """
    Create decorator to require a user session in shibboleth.
    """

    def decorator(f):

        @wraps(f)
        def wrapper(*args, **kwargs):
            if flask.session.get('username'):
                login_user(
                    flask.request,
                    flask.session['username'],
                    flask.session['provider'],
                )
                return f(*args, **kwargs)

            eppn = None
            shib_header = flask.current_app.config.get('SHIBBOLETH_HEADER')
            if shib_header:
                eppn = flask.request.headers.get(shib_header)

            if flask.current_app.config.get('MOCK_AUTH') is True:
                eppn = 'test'
            # if there is authorization header for oauth
            if 'Authorization' in flask.request.headers:
                has_oauth(scope=scope)
                return f(*args, **kwargs)
            # if there is shibboleth session, then create user session and
            # log user in
            elif eppn:
                username = eppn.split('!')[-1]
                flask.session['username'] = username
                flask.session['provider'] = IdentityProvider.itrust
                login_user(flask.request, username, flask.session['provider'])
                return f(*args, **kwargs)
            else:
                raise Unauthorized("Please login")

        return wrapper

    return decorator


def has_oauth(scope=None):
    scope = scope or set()
    scope.update({'access'})
    try:
        user_api = capp.config['USER_API'] if capp.config.has_key('USER_API') else capp.config['HOSTNAME']
        access_token = auth.validate_request_jwt(
            aud=scope, user_api=user_api
        )
    except auth.JWTValidationError as e:
        raise Unauthorized('failed to validate token: {}'.format(e))
    user_id = access_token['sub']
    user = (
        current_session
        .query(User)
        .filter_by(id=user_id)
        .first()
    )
    if not user:
        raise Unauthorized('no user found with id {}'.format(user_id))
    # set some application context for current user and client id
    flask.g.user = user
    # client_id should be None if the field doesn't exist or is empty
    flask.g.client_id = access_token.get('azp') or None
    flask.g.token = access_token


def get_current_user():
    username = flask.session.get('username')
    if not username:
        eppn = flask.request.headers.get(
            flask.current_app.config['SHIBBOLETH_HEADER']
        )
        if flask.current_app.config.get('MOCK_AUTH') is True:
            eppn = 'test'
        if eppn:
            username = eppn.split('!')[-1]
        else:
            raise Unauthorized("User not logged in")
    return (
        current_session.query(User)
        .filter(User.username == username)
        .first()
    )


def get_user_from_token(decoded_jwt):
    username = decoded_jwt["context"]["user"]["name"]
    return current_session.query(
        User).filter(User.username == username).first()
