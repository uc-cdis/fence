from functools import wraps
import json

import flask
from pcdcutils.gen3 import Gen3RequestManager, SignaturePayload

from fence.authz.errors import ArboristError
from fence.errors import Forbidden, Unauthorized, NotFound
from fence.jwt.utils import get_jwt_header
from fence.config import config


def check_arborist_auth(resource, method, constraints=None, check_signature=False):
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
                if check_signature:
                    headers = dict(flask.request.headers)
                    method_s = flask.request.method 
                    path = flask.request.url #flask.request.path
                    body = None
                    if method_s in ['POST', 'PUT', 'PATCH']:
                        body = flask.request.get_json(silent=True)
    
                    g3rm = Gen3RequestManager(headers=headers)

                    if g3rm.is_gen3_signed():
                        # --- PUBLIC_KEY guard ---
                        public_key = config.get("AMANUENSIS_PUBLIC_KEY")
                        if not public_key:
                            flask.current_app.logger.error(
                                "No PUBLIC_KEY configured — cannot validate signature"
                            )
                            raise Forbidden(
                                "Missing PUBLIC_KEY — cannot validate signature"
                            )

                        # --- Prepare SignaturePayload ---
                        payload = SignaturePayload(
                            method=method_s,
                            path=path,
                            headers={
                                "Gen3-Service": headers.get(
                                    "Gen3-Service"
                                )
                            },
                            body = json.dumps(body, separators=(",", ":"))
                        )

                        if not g3rm.valid_gen3_signature(payload, config):
                            raise Forbidden("Gen3 signed request is invalid")
                    else:
                        raise Forbidden(
                            "user does not have privileges to access this endpoint and the signature is not present."
                        )
            return f(*f_args, **f_kwargs)

        return wrapper

    return decorator


def register_arborist_user(user, policies=None):
    if not hasattr(flask.current_app, "arborist"):
        raise Forbidden(
            "this fence instance is not configured with arborist;"
            " this endpoint is unavailable"
        )

    created_user = flask.current_app.arborist.create_user(dict(name=user.username))

    if policies is None:
        if (
            "BASIC_REGISTRATION_ACCESS_POLICY" in config
            and len(config["BASIC_REGISTRATION_ACCESS_POLICY"]) > 0
        ):
            policies = config["BASIC_REGISTRATION_ACCESS_POLICY"]
        else:
            policies = []
            raise NotFound(
                "BASIC_REGISTRATION_ACCESS_POLICY is missing in the configuration file."
            )

    for policy_name in policies:
        policy = flask.current_app.arborist.get_policy(policy_name)
        if not policy:
            raise ArboristError("Policy {} NOT FOUND".format(policy_name))

        res = flask.current_app.arborist.grant_user_policy(user.username, policy_name)
        if res is None:
            raise ArboristError("Policy {} has not been assigned.".format(policy["id"]))


def remove_permission(username=None, policies=None):
    if not hasattr(flask.current_app, "arborist"):
        raise Forbidden(
            "this fence instance is not configured with arborist;"
            " this endpoint is unavailable"
        )

    users = None
    if username is None:
        users = flask.current_app.arborist.get_users()
        # {'users': [{'name': 'graglia01@gmail.com', 'groups': [], 'policies': [{'policy': 'login_no_access', 'expires_at': None}, {'policy': 'gearbox_admin', 'expires_at': None}]}, {'name': 'shea.maunsell@gmail.com', 'groups': [], 'policies': []}, {'name': 'slv@uchicago.edu', 'groups': [], 'policies': []}, {'name': 'furner.brian@gmail.com', 'groups': [], 'policies': []}, {'name': 'bkang.dev@gmail.com', 'groups': [], 'policies': []}, {'name': 'dvenckus@uchicago.edu', 'groups': [], 'policies': []}, {'name': 'lgraglia@uchicago.edu', 'groups': [], 'policies': [{'policy': 'login_no_access', 'expires_at': None}]}, {'name': 'shea@cluelessapp.com', 'groups': [], 'policies': [{'policy': 'login_no_access', 'expires_at': None}]}]}
        users = users.json["users"]
    else:
        user = flask.current_app.arborist.get_user(username)
        users = [user]

    if users and len(users) > 0:
        if policies is None:
            if (
                "BASIC_REGISTRATION_ACCESS_POLICY" in config
                and len(config["BASIC_REGISTRATION_ACCESS_POLICY"]) > 0
            ):
                policies = config["BASIC_REGISTRATION_ACCESS_POLICY"]
            else:
                policies = []

        for policy_name in policies:
            policy = flask.current_app.arborist.get_policy(policy_name)
            if not policy:
                raise ArboristError("Policy {} NOT FOUND".format(policy_name))

            for user in users:
                user_policies = [policy["policy"] for policy in user["policies"]]
                if policy_name in user_policies:
                    res = flask.current_app.arborist.revoke_user_policy(
                        user["name"], policy_name
                    )
                    if res is None:
                        raise ArboristError(
                            "Policy {} has not been revoked from user {}.".format(
                                policy["id"], user["name"]
                            )
                        )
    return "200"
