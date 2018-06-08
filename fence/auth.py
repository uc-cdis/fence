from functools import wraps

from authutils.errors import JWTError, JWTExpiredError
from authutils.token.validate import require_auth_header
from authutils.token.validate import current_token
from authutils.token.validate import set_current_token
from authutils.token.validate import validate_request
import flask
from flask_sqlalchemy_session import current_session
from sqlalchemy import func

from fence.errors import Unauthorized, InternalError
from fence.jwt.validate import validate_jwt
from fence.models import User, IdentityProvider
from fence.user import get_current_user
from fence.utils import clear_cookies


def build_redirect_url(hostname, path):
    """
    Compute a redirect given a hostname and next path where

    Args:
        hostname (str): may be empty string or a bare hostname or
               a hostname with a protocal attached (https?://...)
        path (int): is a path to attach to hostname

    Return:
        string url suitable for flask.redirect
    """
    redirect_base = hostname
    # BASE_URL may be empty or a bare hostname or a hostname with a protocol
    if bool(redirect_base) and not redirect_base.startswith("http"):
        redirect_base = "https://" + redirect_base
    return redirect_base + path


def login_user(request, username, provider):
    user = current_session.query(
        User).filter(func.lower(User.username) == username.lower()).first()
    if not user:
        user = User(username=username)
        idp = (
            current_session.query(IdentityProvider)
            .filter(IdentityProvider.name == provider).first()
        )
        if not idp:
            idp = IdentityProvider(name=provider)
        user.identity_provider = idp
        current_session.add(user)
        current_session.commit()
    flask.g.user = user
    flask.g.scopes = ["_all"]
    flask.g.token = None


def logout(next_url=None):
    # Call get_current_user (but ignore the result) just to check that either
    # the user is logged in or that authorization is mocked.
    user = get_current_user()
    flask.current_app.logger.debug("IN AUTH LOGOUT, next_url = {0}".format(next_url))
    if not user:
        raise Unauthorized("You are not logged in")
    itrust_next_url = None
    if flask.session.get('provider') == IdentityProvider.itrust:
        itrust_next_url = flask.current_app.config['ITRUST_GLOBAL_LOGOUT'] + next_url
    flask.session.clear()
    redirect_response = flask.make_response(
        flask.redirect(itrust_next_url or next_url)
    )
    clear_cookies(redirect_response)
    return redirect_response


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
            enable_shib = (
                'shibboleth' in
                flask.current_app.config.get('ENABLED_IDENTITY_PROVIDERS', [])
            )
            if enable_shib and 'SHIBBOLETH_HEADER' in flask.current_app.config:
                eppn = flask.request.headers.get(
                    flask.current_app.config['SHIBBOLETH_HEADER']
                )

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


def handle_login(scope):
    if flask.session.get('username'):
        login_user(
            flask.request,
            flask.session['username'],
            flask.session['provider'],
        )

    eppn = flask.request.headers.get(
        flask.current_app.config['SHIBBOLETH_HEADER']
    )

    if flask.current_app.config.get('MOCK_AUTH') is True:
        eppn = 'test'
    # if there is authorization header for oauth
    if 'Authorization' in flask.request.headers:
        has_oauth(scope=scope)
    # if there is shibboleth session, then create user session and
    # log user in
    elif eppn:
        username = eppn.split('!')[-1]
        flask.session['username'] = username
        flask.session['provider'] = IdentityProvider.itrust
        login_user(flask.request, username, flask.session['provider'])
    else:
        raise Unauthorized("Please login")


def has_oauth(scope=None):
    scope = scope or set()
    scope.update({'openid'})
    try:
        access_token_claims = validate_jwt(aud=scope, purpose='access')
    except JWTError as e:
        raise Unauthorized('failed to validate token: {}'.format(e))
    user_id = access_token_claims['sub']
    user = current_session.query(User).filter_by(id=int(user_id)).first()
    if not user:
        raise Unauthorized('no user found with id: {}'.format(user_id))
    # set some application context for current user and client id
    flask.g.user = user
    # client_id should be None if the field doesn't exist or is empty
    flask.g.client_id = access_token_claims.get('azp') or None
    flask.g.token = access_token_claims


def get_user_from_claims(claims):
    return (
        current_session
        .query(User)
        .filter(User.id == claims['sub'])
        .first()
    )

def admin_required(f):
    """
    Require user to be an admin user. 
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not flask.g.user:
            raise Unauthorized("Require login")
        if flask.g.user.is_admin is not True:
            raise Unauthorized("Require admin user")
        return f(*args, **kwargs)
    return wrapper
