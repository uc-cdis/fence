import flask
from flask_sqlalchemy_session import current_session
from functools import wraps
import urllib.request, urllib.parse, urllib.error

from authutils.errors import JWTError, JWTExpiredError
from authutils.token.validate import (
    current_token,
    require_auth_header,
    set_current_token,
    validate_request,
)
from cdislogging import get_logger

from fence.errors import Unauthorized, InternalError
from fence.jwt.validate import validate_jwt
from fence.models import User, IdentityProvider, query_for_user
from fence.user import get_current_user
from fence.utils import clear_cookies
from fence.config import config

logger = get_logger(__name__)


def get_jwt():
    """
    Return the user's JWT from authorization header. Requires flask application context.
    Raises:
        - Unauthorized, if header is missing or not in the correct format
    """
    header = flask.request.headers.get("Authorization")
    if not header:
        raise Unauthorized("missing authorization header")
    try:
        bearer, token = header.split(" ")
    except ValueError:
        raise Unauthorized("authorization header not in expected format")
    if bearer.lower() != "bearer":
        raise Unauthorized("expected bearer token in auth header")
    return token


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


def login_user(
    username, provider, fence_idp=None, shib_idp=None, email=None, id_from_idp=None
):
    """
    Login a user with the given username and provider. Set values in Flask
    session to indicate the user being logged in. In addition, commit the user
    and associated idp information to the db.

    Args:
        username (str): specific username of user to be logged in
        provider (str): specfic idp of user to be logged in
        fence_idp (str, optional): Downstreawm fence IdP
        shib_idp (str, optional): Downstreawm shibboleth IdP
        email (str, optional): email of user (may or may not match username depending
            on the IdP)
        id_from_idp (str, optional): id from the IDP (which may be different than
            the username)
    """

    def set_flask_session_values(user):
        """
        Helper fuction to set user values in the session.

        Args:
            user (User): User object
        """
        flask.session["username"] = user.username
        flask.session["user_id"] = str(user.id)
        flask.session["provider"] = user.identity_provider.name
        if fence_idp:
            flask.session["fence_idp"] = fence_idp
        if shib_idp:
            flask.session["shib_idp"] = shib_idp
        flask.g.user = user
        flask.g.scopes = ["_all"]
        flask.g.token = None

    user = query_for_user(session=current_session, username=username)
    if user:
        _update_users_email(user, email)
        _update_users_id_from_idp(user, id_from_idp)

        #  This expression is relevant to those users who already have user and
        #  idp info persisted to the database. We return early to avoid
        #  unnecessarily re-saving that user and idp info.
        if user.identity_provider and user.identity_provider.name == provider:
            set_flask_session_values(user)
            return
    else:
        # we need a new user
        user = User(username=username)

        if email:
            user.email = email

        if id_from_idp:
            user.id_from_idp = id_from_idp

    # setup idp connection for new user (or existing user w/o it setup)
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

    set_flask_session_values(user)


def logout(next_url, force_era_global_logout=False):
    """
    Return a redirect which another logout from IDP or the provided redirect.
    Depending on the IDP, this logout will propogate. For example, if using
    another fence as an IDP, this will hit that fence's logout endpoint.
    Args:
        next_url (str): Final redirect desired after logout
    """
    logger.debug("IN AUTH LOGOUT, next_url = {0}".format(next_url))

    # propogate logout to IDP
    provider_logout = None
    provider = flask.session.get("provider")
    if force_era_global_logout or provider == IdentityProvider.itrust:
        safe_url = urllib.parse.quote_plus(next_url)
        provider_logout = config["ITRUST_GLOBAL_LOGOUT"] + safe_url
    elif provider == IdentityProvider.fence:
        base = config["OPENID_CONNECT"]["fence"]["api_base_url"]
        provider_logout = base + "/logout?" + urllib.parse.urlencode({"next": next_url})

    flask.session.clear()
    redirect_response = flask.make_response(
        flask.redirect(provider_logout or urllib.parse.unquote(next_url))
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
                login_user(flask.session["username"], flask.session["provider"])
                return f(*args, **kwargs)

            eppn = None
            if config["LOGIN_OPTIONS"]:
                enable_shib = "shibboleth" in [
                    option["idp"] for option in config["LOGIN_OPTIONS"]
                ]
            else:
                # fall back on "providers"
                enable_shib = "shibboleth" in (
                    config.get("ENABLED_IDENTITY_PROVIDERS") or {}
                ).get("providers", {})

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
                login_user(username, flask.session["provider"])
                return f(*args, **kwargs)
            else:
                raise Unauthorized("Please login")

        return wrapper

    return decorator


def has_oauth(scope=None):
    scope = scope or set()
    scope.update({"openid"})
    try:
        access_token_claims = validate_jwt(
            scope=scope,
            purpose="access",
        )
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


def _update_users_email(user, email):
    """
    Update email if provided and doesn't match db entry.
    """
    if email and user.email != email:
        logger.info(
            f"Updating username {user.username}'s email from {user.email} to {email}"
        )
        user.email = email

        current_session.add(user)
        current_session.commit()


def _update_users_id_from_idp(user, id_from_idp):
    """
    Update id_from_idp if provided and doesn't match db entry.
    """
    if id_from_idp and user.id_from_idp != id_from_idp:
        logger.info(
            f"Updating username {user.username}'s id_from_idp from {user.id_from_idp} to {id_from_idp}"
        )
        user.id_from_idp = id_from_idp

        current_session.add(user)
        current_session.commit()
