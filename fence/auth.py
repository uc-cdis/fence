from functools import wraps
import urllib

from authutils.errors import JWTError, JWTExpiredError
from authutils.token.validate import require_auth_header
from authutils.token.validate import current_token
from authutils.token.validate import set_current_token
from authutils.token.validate import validate_request
import flask
from flask_sqlalchemy_session import current_session

from fence.errors import Unauthorized, InternalError
from fence.jwt.validate import validate_jwt
from fence.models import User, IdentityProvider, query_for_user
from fence.user import get_current_user
from fence.utils import clear_cookies
from fence.config import config


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
    user = query_for_user(session=current_session, username=username)

    if not user:
        user = User(username=username)
        idp = (
            current_session.query(IdentityProvider)
            .filter(IdentityProvider.name == provider)
            .first()
        )
        if not idp:
            idp = IdentityProvider(name=provider)
        user.identity_provider = idp
        current_session.add(user)
        current_session.commit()
    flask.session["username"] = username
    flask.session["provider"] = provider
    flask.session["user_id"] = str(user.id)
    flask.g.user = user
    flask.g.scopes = ["_all"]
    flask.g.token = None


def logout(next_url):
    """
    Return a redirect which another logout from IDP or the provided redirect.

    Depending on the IDP, this logout will propogate. For example, if using
    another fence as an IDP, this will hit that fence's logout endpoint.

    Args:
        next_url (str): Final redirect desired after logout
    """
    flask.current_app.logger.debug("IN AUTH LOGOUT, next_url = {0}".format(next_url))

    # propogate logout to IDP
    provider_logout = None
    provider = flask.session.get("provider")
    if provider == IdentityProvider.itrust:
        safe_url = urllib.quote_plus(next_url)
        provider_logout = config["ITRUST_GLOBAL_LOGOUT"] + safe_url
    elif provider == IdentityProvider.fence:
        base = config["OPENID_CONNECT"]["fence"]["api_base_url"]
        safe_url = urllib.quote_plus(next_url)
        provider_logout = base + "/logout?" + urllib.urlencode({"next": safe_url})

    flask.session.clear()
    redirect_response = flask.make_response(
        flask.redirect(provider_logout or urllib.unquote(next_url))
    )
    clear_cookies(redirect_response)
    return redirect_response


def check_scope(scope):
    def wrapper(f):
        @wraps(f)
        def check_scope_and_call(*args, **kwargs):
            if "_all" in flask.g.scopes or scope in flask.g.scopes:
                return f(*args, **kwargs)
            else:
                raise Unauthorized(
                    "Requested scope {} can't access this endpoint".format(scope)
                )

        return check_scope_and_call

    return wrapper


def login_required(scope=None):
    """
    Create decorator to require a user session
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if flask.session.get("username"):
                login_user(
                    flask.request, flask.session["username"], flask.session["provider"]
                )
                return f(*args, **kwargs)

            eppn = None
            enable_shib = "shibboleth" in config.get("ENABLED_IDENTITY_PROVIDERS", [])
            if enable_shib and "SHIBBOLETH_HEADER" in config:
                eppn = flask.request.headers.get(config["SHIBBOLETH_HEADER"])

            if config.get("MOCK_AUTH") is True:
                eppn = "test"
            # if there is authorization header for oauth
            if "Authorization" in flask.request.headers:
                has_oauth(scope=scope)
                return f(*args, **kwargs)
            # if there is shibboleth session, then create user session and
            # log user in
            elif eppn:
                username = eppn.split("!")[-1]
                flask.session["username"] = username
                flask.session["provider"] = IdentityProvider.itrust
                login_user(flask.request, username, flask.session["provider"])
                return f(*args, **kwargs)
            else:
                raise Unauthorized("Please login")

        return wrapper

    return decorator


def handle_login(scope):
    if flask.session.get("username"):
        login_user(flask.request, flask.session["username"], flask.session["provider"])

    eppn = flask.request.headers.get(config["SHIBBOLETH_HEADER"])

    if config.get("MOCK_AUTH") is True:
        eppn = "test"
    # if there is authorization header for oauth
    if "Authorization" in flask.request.headers:
        has_oauth(scope=scope)
    # if there is shibboleth session, then create user session and
    # log user in
    elif eppn:
        username = eppn.split("!")[-1]
        flask.session["username"] = username
        flask.session["provider"] = IdentityProvider.itrust
        login_user(flask.request, username, flask.session["provider"])
    else:
        raise Unauthorized("Please login")


def has_oauth(scope=None):
    scope = scope or set()
    scope.update({"openid"})
    try:
        access_token_claims = validate_jwt(aud=scope, purpose="access")
    except JWTError as e:
        raise Unauthorized("failed to validate token: {}".format(e))
    user_id = access_token_claims["sub"]
    user = current_session.query(User).filter_by(id=int(user_id)).first()
    if not user:
        raise Unauthorized("no user found with id: {}".format(user_id))
    # set some application context for current user and client id
    flask.g.user = user
    # client_id should be None if the field doesn't exist or is empty
    flask.g.client_id = access_token_claims.get("azp") or None
    flask.g.token = access_token_claims


def get_user_from_claims(claims):
    return current_session.query(User).filter(User.id == claims["sub"]).first()


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


def admin_login_required(function):
    """Compose the login required and admin required decorators."""
    return login_required({"admin"})(admin_required(function))
