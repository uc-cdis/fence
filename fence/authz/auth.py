from functools import wraps

import flask

from fence.errors import Forbidden
from fence.jwt.utils import get_jwt_header


def authorize(resource, method):
    """
    Check with arborist to verify the authz for a request.

    Args:
        resource (str or list[str]):
            Identifier for the thing being accessed. These look like filepaths. This
            ``resource`` must correspond to some resource entered previously in
            arborist. Currently the existing resources are going to be the
            program/projects set up by the user sync.
        method (str or list[str]):
            Identifier for the action the user is trying to do. Like ``resource``, this
            is something that has to exist in arborist already.
    """
    if not hasattr(flask.current_app, "arborist"):
        raise Forbidden(
            "this fence instance is not configured with arborist;"
            " this endpoint is unavailable"
        )
    if not flask.current_app.arborist.auth_request(
        jwt=get_jwt_header(),
        service="fence",
        methods=method,
        resources=resource,
    ):
        raise Forbidden("user does not have privileges to access this endpoint")


def check_arborist_auth(resource, method):
    """
    Same as `authorize`, but as a decorator.

    Return:
        Callable: decorator
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*f_args, **f_kwargs):
            authorize(resource, method)
            return f(*f_args, **f_kwargs)

        return wrapper

    return decorator
