from functools import wraps

import flask

from fence.authz.errors import ArboristError
from fence.errors import Forbidden, Unauthorized
from fence.jwt.utils import get_jwt_header


def check_arborist_auth(resource, method, constraints=None):
    """
    Check with arborist to verify the authz for a request.

    TODO (rudyardrichter, 2018-12-21):
    update as necessary as changes happen to ABAC & arborist

    Args:
        resource (str):
            Identifier for the thing being accessed. These look like filepaths. This
            ``resource`` must correspond to some resource entered previously in
            arborist. Currently the existing resources are going to be the
            program/projects set up by the user sync.
        method (str):
            Identifier for the action the user is trying to do. Like ``resource``, this
            is something that has to exist in arborist already.
        constraints (Optional[Dict[str, str]]):
            Optional set of constraints to send to arborist for context on this request.
            (These really aren't used at all yet.)

    Return:
        Callable: decorator
    """
    constraints = constraints or {}

    def decorator(f):
        @wraps(f)
        def wrapper(*f_args, **f_kwargs):
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
            return f(*f_args, **f_kwargs)

        return wrapper

    return decorator



def register_arborist_user(user):
    if not hasattr(flask.current_app, "arborist"):
        raise Forbidden(
            "this fence instance is not configured with arborist;"
            " this endpoint is unavailable"
        )

    policy = flask.current_app.arborist.get_policy("login_no_access")
    if not policy:
        raise NotFound(
            "Policy {} NOT FOUND".format(
                "login_no_access"
            )
        )


    created_user = flask.current_app.arborist.create_user(dict(name=user.username))

    res = flask.current_app.arborist.grant_user_policy(user.username, "login_no_access")
    if res is None:
        raise ArboristError(
            "Policy {} has not been assigned.".format(
                policy["id"]
            )
        )
    

       # with flask.current_app.arborist.context(authz_provider="synapse"):
       #      if config["DREAM_CHALLENGE_TEAM"] in token_result.get("team", []):
       #          # make sure the user exists in Arborist
       #          flask.current_app.arborist.create_user(dict(name=user.username))
       #          flask.current_app.arborist.add_user_to_group(
       #              user.username,
       #              config["DREAM_CHALLENGE_GROUP"],
       #              datetime.now(timezone.utc)
       #              + timedelta(seconds=config["SYNAPSE_AUTHZ_TTL"]),
       #          )
       #      else:
       #          flask.current_app.arborist.remove_user_from_group(
       #              user.username, config["DREAM_CHALLENGE_GROUP"]
       #          )


    
