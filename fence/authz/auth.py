from functools import wraps

from cdislogging import get_logger
from fence import config
import flask
from gen3authz.utils import is_path_prefix_of_path

from fence.errors import Forbidden, Unauthorized
from fence.jwt.utils import get_jwt_header


logger = get_logger(__name__)


def authorize(resource, method, token=None, user_id=None):
    """
    Check with arborist to verify the authz for a request. Throws a ``Forbidden`` error if the user is not authorized to access the resource.

    WARNING: If you pass user_id, then Arborist does not do token validation. So ensure that has happened
             BEFORE this call!

    Args:
        resource (str or list[str]):
            Identifier for the thing being accessed. These look like filepaths. This
            ``resource`` must correspond to some resource entered previously in
            arborist. Currently the existing resources are going to be the
            program/projects set up by the user sync.
        method (str or list[str]):
            Identifier for the action the user is trying to do. Like ``resource``, this
            is something that has to exist in arborist already.
        token (str):
            If not provided, falls back to the token provided in the `Authorization` header.
        user_id (str):
            Username to authorize instead of a token. Takes precedence over `token` in
            arborist. Prefer this for tokens fence itself issued: decoding one requires
            arborist to fetch fence's JWKS, which fence cannot serve while it is waiting
            on this call.
    """
    if not hasattr(flask.current_app, "arborist") or not flask.current_app.arborist:
        raise Forbidden(
            "this fence instance is not configured with arborist;"
            " this endpoint is unavailable"
        )
    if not user_id and not token:
        if "Authorization" not in flask.request.headers:
            logger.debug("request missing Authorization header; treating as anonymous")
            token = None
        else:
            token = get_jwt_header()

    if not flask.current_app.arborist.auth_request(
        jwt=token,
        user_id=user_id,
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


def can_user_get_task_token(
    task_token_type: str, expires_in: int, username: str
) -> bool:
    """
    Checks a requested expiration against the user's authz.
    Example: a user with access to `/services/fence/task-token/FOO/100` can request a
    task token of type "FOO" that expires exactly in 100 seconds.

    A user with access to `/services/fence/task-token/FOO` (no exact value)
    can request a task token of any expiration.

    Args:
        task_token_type (str): the type of task token being requested
        expires_in (int): the requested expiration in seconds
        username (str): the user's username, used to check authz

    Returns:
        bool: True if the user is authorized to request a task token of the given type and expiration, False otherwise
    """

    if not isinstance(expires_in, int) or isinstance(expires_in, bool):
        return False
    if expires_in <= 0:
        return False

    max_task_token_ttl = config["MAX_TASK_TOKEN_TTL"].get(
        task_token_type, config["MAX_ACCESS_TOKEN_TTL"]
    )
    if expires_in > max_task_token_ttl:
        return False

    # Check if the user has a policy providing access to create a task token
    # of the requested type and expiration.
    # Note: Arborist policies are hierarchical, so a policy granting access to `/services/fence/task-token/FOO` (no expiration)
    # will also grant access to `/services/fence/task-token/FOO/100`.
    resource_path = f"/services/fence/task-token/{task_token_type}/{expires_in}"

    try:
        authorize(resource=resource_path, method="create", user_id=username)
        return True
    except Forbidden:
        return False
