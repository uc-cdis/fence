import flask

from fence.errors import Unauthorized


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
            response = flask.current_app.arborist.auth_request(json=data)

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
