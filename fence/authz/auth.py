from functools import wraps

from cdislogging import get_logger
import flask
from gen3authz.utils import is_path_prefix_of_path

from fence.errors import Forbidden, Unauthorized
from fence.jwt.utils import get_jwt_header


logger = get_logger(__name__)


def authorize(resource, method):
    """
    Check with arborist to verify the authz for a request. Throws a ``Forbidden`` error if the user is not authorized to access the resource.

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
    if "Authorization" not in flask.request.headers:
        logger.debug("request missing Authorization header; treating as anonymous")
        token = None  # anonymous
    else:
        token = get_jwt_header()

    if not flask.current_app.arborist.auth_request(
        jwt=token,
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


def can_user_get_task_token(username, task_token_type, expires_in):
    """
    Checks a requested expiration against the user's authz mapping.
    Example: a user with access to `/services/fence/task-token/FOO/100` can request a
    task token of type "FOO" that expires in up to 100 seconds.
    """
    resource_path = f"/services/fence/task-token/{task_token_type}"
    mapping = (
        flask.current_app.arborist.auth_mapping(username=username)
        if flask.current_app.arborist
        else {}
    )

    for authorized_path, access in mapping.items():
        authorized_path_without_exp = authorized_path.split(f"/{task_token_type}/")[0]
        if not is_path_prefix_of_path(authorized_path_without_exp, resource_path):
            # the path does not match
            continue

        if not any(
            e["service"] in ["fence", "*"] and e["method"] in ["create", "*"]
            for e in access
        ):
            # the service and/or method do not match
            continue

        if f"{resource_path}/" not in authorized_path:
            # no max expiration in the path: the user has access to create task tokens of
            # any lifetime
            return True

        # parse from the resource path the max lifetime the user is allowed to request
        max_authorized_exp = authorized_path.split(f"{resource_path}/")[1].split("/")[0]
        try:
            max_authorized_exp = int(max_authorized_exp)
        except ValueError:
            logger.warning(
                f"Invalid max expiration in user's resource path '{authorized_path}'"
            )
            return False

        # check whether the user has access to tokens of the requested lifetime
        if expires_in > max_authorized_exp:
            logger.debug(
                f"User is requesting a task token lifetime ({expires_in}) larger than they have access to ('{authorized_path}')"
            )
            return False

        return True

    return False
