from functools import wraps

from cdispyutils import auth
from flask import session, g, request
from flask import current_app as capp
from flask_sqlalchemy_session import current_session

from .errors import Unauthorized, InternalError
from .models import User, IdentityProvider


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
    g.user = user
    g.scopes = ["_all"]


def logout(next_url=None):
    # Call get_current_user (but ignore the result) just to check that either
    # the user is logged in or that authorization is mocked.
    get_current_user()
    if session['provider'] == IdentityProvider.itrust:
        next_url = capp.config['ITRUST_GLOBAL_LOGOUT'] + next_url
    session.clear()
    return next_url


def check_scope(scope):
    def wrapper(f):
        @wraps(f)
        def check_scope_and_call(*args, **kwargs):
            if '_all' in g.scopes or scope in g.scopes:
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
            if session.get('username'):
                login_user(request, session['username'], session['provider'])
                return f(*args, **kwargs)

            eppn = request.headers.get(capp.config['SHIBBOLETH_HEADER'])

            if capp.config.get('MOCK_AUTH') is True:
                eppn = 'test'
            # if there is authorization header for oauth
            if 'Authorization' in request.headers:
                has_oauth(request.headers['Authorization'], scope=scope)
                return f(*args, **kwargs)
            # if there is shibboleth session, then create user session and
            # log user in
            elif eppn:
                username = eppn.split('!')[-1]
                session['username'] = username
                session['provider'] = IdentityProvider.itrust
                login_user(request, username, session['provider'])
                return f(*args, **kwargs)
            else:
                raise Unauthorized("Please login")

        return wrapper

    return decorator


def has_oauth(scope=None):
    scope = scope or set()
    scope.update('access')
    try:
        access_token = auth.validate_request_jwt(aud=scope)
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
    g.user = user


def get_current_user():
    username = session.get('username')
    if not username:
        eppn = request.headers.get(capp.config['SHIBBOLETH_HEADER'])
        if capp.config.get('MOCK_AUTH') is True:
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
