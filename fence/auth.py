from functools import wraps

from addict import Dict
from authutils.errors import JWTError
from authutils.token import current_token, set_current_token
import flask

from fence.errors import Unauthorized
from fence.jwt.validate import validate_jwt
from fence.models import IdentityProvider, User


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


def logout(next_url=None):
    # Call get_current_user (but ignore the result) just to check that either
    # the user is logged in or that authorization is mocked.
    if not current_token:
        raise Unauthorized("You are not logged in")
    if flask.session.get('provider') == IdentityProvider.itrust:
        next_url = flask.current_app.config['ITRUST_GLOBAL_LOGOUT'] + next_url
    flask.session.clear()
    return next_url


def set_validated_token(*args, **kwargs):
    mocked_token = flask.current_app.config.get('MOCK_AUTH')
    if mocked_token:
        set_current_token(mocked_token)
    else:
        set_current_token(validate_jwt(*args, **kwargs))


def require_auth(*args, **kwargs):
    """
    Return a function decorator to require a JWT auth header with certain
    constraints.

    The arguments of this function are passed through to
    ``fence.jwt.validate.validate_jwt``.
    """

    def decorator(f):
        """Decorate the function ``f`` with the token wrapper."""

        @wraps(f)
        def wrapper(*f_args, **f_kwargs):
            """Wrap ``f`` to validate and set the current token."""
            set_validated_token(*args, **kwargs)
            return f(*f_args, **f_kwargs)

        return wrapper

    return decorator


def require_admin(f):
    """
    Decorate a function to require that the current user has admin privileges.
    Should be used as a decorator following ``require_auth``, for example:

    .. code-block:: python

        @blueprint.route('/admin-only')
        @require_admin
        @require_auth(aud={'openid'}, purpose='access')
        def admin_endpoint():
            return 'user is admin'

    (This is because of the use of ``current_token``, which is set by
    ``require_auth``.)

    Args:
        f (Callable): a function already be decorated with ``require_auth``

    Return:
        Callable: the wrapped function
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        """Wrap ``f`` to raise error if user is not authorized as admin."""
        try:
            is_admin = current_token['context']['user']['is_admin']
        except KeyError as e:
            raise JWTError('missing field in current token: {}'.format(str(e)))
        if not is_admin:
            raise Unauthorized('user is not admin')
        return f(*args, **kwargs)

    return wrapper
