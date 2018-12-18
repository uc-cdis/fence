from functools import wraps

import flask

from fence.errors import Forbidden, Unauthorized


def check_arborist_auth(resource, method, constraints=None):
    """
    Return a function decorator to send an auth request to arborist.

    Args:
        resource (str):
        method (str):
        constraints (Dict[str, str]):

    Return:
        Callable: decorator
    """
    constraints = constraints or {}

    def decorator(f):

        @wraps(f)
        def wrapper(*f_args, **f_kwargs):
            if not hasattr(flask.current_app, "arborist"):
                raise Forbidden(
                    "this fence instance is not configured for role-based access"
                    " control; this endpoint is unavailable"
                )

            jwt = _get_jwt_header()
            data = {
                "user": {
                    "token": jwt,
                },
                "request": {
                    "resource": resource,
                    "action": {"service": "fence", "method": method},
                }
            }
            if not flask.current_app.arborist.auth_request(data=data):
                raise Forbidden(
                    "user does not have privileges to access this endpoint"
                )
            return f(*f_args, **f_kwargs)

        return wrapper

    return decorator


def _get_jwt_header():
    """
    Get the user's JWT from the Authorization header, or raise Unauthorized on failure.
    """
    try:
        header = flask.request.headers["Authorization"]
    except KeyError:
        raise Unauthorized("missing authorization header")
    if not header.lower().startswith("bearer"):
        raise Unauthorized("unexpected Authorization header format (expected `Bearer`")
    try:
        jwt = header.split(" ")[1]
    except IndexError:
        raise Unauthorized("authorization header missing token")
    return jwt
