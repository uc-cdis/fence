"""
Blueprints for administation of the userdatamodel database and the storage
solutions. Operations here assume the underlying operations in the interface
will maintain coherence between both systems.
"""

import functools

from flask import request, jsonify, Blueprint, current_app

from gen3authz.client.arborist.client import ArboristClient
from cdislogging import get_logger

from fence.auth import admin_login_required
from fence.authz.errors import ArboristError
from fence.authz.auth import remove_permission
from fence.resources.audit.utils import enable_request_logging
from fence.resources import admin
from fence.scripting.fence_create import sync_users
from fence.config import config
from fence.models import User, DocumentSchema
from fence.errors import UserError, NotFound, InternalError




logger = get_logger(__name__)


blueprint = Blueprint("admin", __name__)


#### USERS ####


@blueprint.route("/users/<username>", methods=["GET"])
@blueprint.route("/user/<username>", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_user(username):
    """
    Get the information of a user from our userdatamodel database

    Returns a json object
    """
    return jsonify(admin.get_user_info(current_app.scoped_session(), username))


@blueprint.route("/users", methods=["GET"])
@blueprint.route("/user", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_all_users():
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Get the information of all users from our userdatamodel database

    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(admin.get_all_users(current_app.scoped_session()))


@blueprint.route("/users/selected", methods=["POST"])
@blueprint.route("/user/selected", methods=["POST"])
@admin_login_required
@enable_request_logging
def get_users():
    """
    Get the information about each user included in the submitted username list from our 
    userdatamodel database

    Returns a json object of one or more user records
    """
    usernames = request.get_json().get('usernames', None)
    ids = request.get_json().get('ids', None)
    
    if (ids and usernames):
        raise UserError("Wrong params, only one among `ids` and `usernames` should be set.")

    if usernames:
        users = admin.get_users(current_app.scoped_session(), usernames)
    elif ids:
        users = admin.get_users_by_id(current_app.scoped_session(), ids)
    else:
        raise UserError("Wrong params, at least one among `ids` and `usernames` should be set.")
        
    return jsonify(users)


@blueprint.route("/users", methods=["POST"])
@blueprint.route("/user", methods=["POST"])
@admin_login_required
@enable_request_logging
def create_user():
    """
    Create a user on the userdatamodel database

    Returns a json object
    """
    username = request.get_json().get("username", None)
    email = request.get_json().get("email", None)
    display_name = request.get_json().get("display_name", None)
    phone_number = request.get_json().get("phone_number", None)
    idp_name = request.get_json().get("idp_name", None)
    tags = request.get_json().get("tags", None)

    return jsonify(
        admin.create_user(
            current_app.scoped_session(),
            username,
            email,
            display_name,
            phone_number,
            idp_name,
            tags,
        )
    )


@blueprint.route("/users/<username>", methods=["PUT"])
@blueprint.route("/user/<username>", methods=["PUT"])
@admin_login_required
@enable_request_logging
def update_user(username):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user on the userdatamodel database

    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    new_username = request.get_json().get("username", None)
    role = request.get_json().get("role", None)
    email = request.get_json().get("email", None)
    return jsonify(
        admin.update_user(
            current_app.scoped_session(), username, role, email, new_username
        )
    )


@blueprint.route("/users/<username>", methods=["DELETE"])
@blueprint.route("/user/<username>", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def delete_user(username):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Remove the user from the userdatamodel database and all associated storage
    solutions.

    Returns json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    response = jsonify(admin.delete_user(current_app.scoped_session(), username))
    return response


@blueprint.route("/users/<username>/soft", methods=["DELETE"])
@blueprint.route("/user/<username>/soft", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def soft_delete_user(username):
    """
    Soft-remove the user by marking it as active=False.

    Returns json object
    """
    response = jsonify(admin.soft_delete_user(current_app.scoped_session(), username))
    return response


@blueprint.route("/users/<username>/groups", methods=["GET"])
@blueprint.route("/user/<username>/groups", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_user_groups(username):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Get the information of a user from our userdatamodel database.

    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(admin.get_user_groups(current_app.scoped_session(), username))


@blueprint.route("/users/<username>/groups", methods=["PUT"])
@blueprint.route("/user/<username>/groups", methods=["PUT"])
@admin_login_required
@enable_request_logging
def add_user_to_groups(username):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user to group relationship in the database

    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    groups = request.get_json().get("groups", [])
    return jsonify(
        admin.add_user_to_groups(current_app.scoped_session(), username, groups=groups)
    )


@blueprint.route("/users/<username>/groups", methods=["DELETE"])
@blueprint.route("/user/<username>/groups", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def remove_user_from_groups(username):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user to group relationship in the database

    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    groups = request.get_json().get("groups", [])
    return jsonify(
        admin.remove_user_from_groups(
            current_app.scoped_session(), username, groups=groups
        )
    )


@blueprint.route("/users/<username>/projects", methods=["DELETE"])
@blueprint.route("/user/<username>/projects", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def remove_user_from_projects(username):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user to group relationship in the database

    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    projects = request.get_json().get("projects", [])
    return jsonify(
        admin.remove_user_from_projects(
            current_app.scoped_session(), username, projects
        )
    )


@blueprint.route("/users/<username>/projects", methods=["PUT"])
@blueprint.route("/user/<username>/projects", methods=["PUT"])
@admin_login_required
@enable_request_logging
def add_user_to_projects(username):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user to project relationship on the database and add the access to
    the the object store associated with it

    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    projects = request.get_json().get("projects", [])
    return jsonify(
        admin.add_user_to_projects(
            current_app.scoped_session(), username, projects=projects
        )
    )

# DEPRECATED
@blueprint.route("/toggle_admin", methods=["POST"])
@admin_login_required
@enable_request_logging
def toggle_admin():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_resource`

    payload:
    `{
        "parent_path": "/services/",
        "name": "amanuensis",
        "description": "Amanuensis admin resource"
    }`
    """
    body = request.get_json()
    user_id = body.get('user_id', None)

    if user_id is None:
        raise UserError("There are some missing parameters in the payload.")

    res = admin.toggle_admin(current_app.scoped_session(), user_id)
    if res is None or len(res) < 1:
        raise InternalError(
            "Resource {} has not been created.".format(
                user_id
            )
        )
    else:
        logger.info("Updated resource")

    return jsonify(res)

@blueprint.route("/update_user_authz", methods=["POST"])
@admin_login_required
@enable_request_logging
def update_user_authz():
    """
    run user sync to update fence anf arborist DB

    Receive a JSON object with the list of resources, policies, roles, and user auth

    Returns a json object
    """

    logger.warning("IN UPDATE")
    logger.warning(request.get_json())

    sync_users(
            dbGaP=[{'info': {'host': '', 'username': '', 'password': '', 'port': 22, 'proxy': '', 'proxy_user': ''}, 'protocol': 'sftp', 'decrypt_key': '', 'parse_consent_code': True}], # dbGap
            STORAGE_CREDENTIALS={}, # storage_credential
            DB=config["DB"], # flask.current_app.db, # postgresql://fence_user:fence_pass@postgres:5432/fence_db DB
            projects=None, #project_mapping
            is_sync_from_dbgap_server=False,
            sync_from_local_csv_dir=None,
            sync_from_local_yaml_file=None, #'user.yaml',
            json_from_api=request.get_json(),
            arborist=flask.current_app.arborist,
            folder=None,
        )

    # username = request.get_json().get("name", None)
    # role = request.get_json().get("role", None)
    # email = request.get_json().get("email", None)
    # return jsonify(admin.create_user(current_app.scoped_session(), username, role, email))
    return jsonify("test")


@blueprint.route("/add_resource", methods=["POST"])
@admin_login_required
@enable_request_logging
def add_resource():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_resource`

    payload:
    `{
        "parent_path": "/services/",
        "name": "amanuensis",
        "description": "Amanuensis admin resource"
    }`
    """
    body = request.get_json()

    parent_path = body.get('parent_path', None)
    name = body.get('name', None)
    description = body.get('description', None)

    if name is None:
        raise UserError("There are some missing parameters in the payload.")

    resource_json = {}
    resource_json["name"] = name
    resource_json["description"] = description
    res = current_app.arborist.create_resource(parent_path, resource_json)
    if res is None:
        raise ArboristError(
            "Resource {} has not been created.".format(
                resource_json
            )
        )
    else:
        logger.info("Created resource {}".format(resource_json))

    return jsonify(res)


@blueprint.route("/add_role", methods=["POST"])
@admin_login_required
@enable_request_logging
def add_role():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_role`

    payload:
    `{
        "id": "amanuensis_admin",
        "description": "can do admin work on project/data request",
        "permissions": [
            {
                "id": "amanuensis_admin_action", 
                "action": {
                    "service": "amanuensis", 
                    "method": "*"
                }
            }
        ]
    }`
    """
    body = request.get_json()

    id = body.get('id', None)
    description = body.get('description', None)
    permissions = body.get('permissions', None)

    if id is None or permissions is None:
        raise UserError("There are some missing parameters in the payload.")

    role_json = {}
    role_json["id"] = id
    role_json["description"] = description
    role_json["permissions"] = permissions
    res = current_app.arborist.create_role(role_json)
    if res is None:
        raise ArboristError(
            "Role {} has not been created.".format(
                role_json
            )
        )
    else:
        logger.info("Created role {}".format(role_json))

    return jsonify(res)


@blueprint.route("/add_policy", methods=["POST"])
@admin_login_required
@enable_request_logging
def add_policy():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_policy`

    payload:
    `{
        "id": "services.amanuensis-admin",
        "description": "admin access to amanunsis",
        "resource_paths": [
            "/services/amanuensis"
        ],
        "role_ids": [
            "amanuensis_admin"
        ]   
    }`
    """
    body = request.get_json()

    policy_id = body.get('id', None)
    description = body.get('description', None)
    resource_paths = body.get('resource_paths', None)
    role_ids = body.get('role_ids', None)

    if policy_id is None or resource_paths is None or role_ids is None:
        raise UserError("There are some missing parameters in the payload.")

    # Check if resource exists
    for path in resource_paths:
        resource = current_app.arborist.get_resource(path)
        if resource is None:
            raise NotFound("Resource {} not found".format(path))

    # Check if role exists
    # TODO gen3authz 1.4.2 doens't support get_role, create a PR or see if future versions support that.
    roles = current_app.arborist.list_roles()
    arborist_role_ids = [role["id"] for role in roles.json["roles"]]
    for id in role_ids:
        if id not in arborist_role_ids:
            raise NotFound("Role {} not found.".format(id))

    policy_json = {}
    policy_json["id"] = policy_id
    policy_json["description"] = description
    policy_json["resource_paths"] = resource_paths
    policy_json["role_ids"] = role_ids
    res = current_app.arborist.create_policy(policy_json)
    if res is None:
        raise ArboristError(
            "Policy {} has not been created.".format(
                policy_json
            )
        )
    else:
        logger.info("Created policy {}".format(policy_json))

    return jsonify(res)


@blueprint.route("/add_policy_to_user", methods=["POST"])
@admin_login_required
@enable_request_logging
def add_policy_to_user():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_policy_to_user`

    payload:
    `{
       "policy_name" = "services.amanuensis-admin",
       "username" = "graglia01@gmail.com"
    }`
    """
    body = request.get_json()

    policy_name = body.get('policy_name', None)
    username = body.get('username', None)

    if username is None or policy_name is None:
        raise UserError("There are some missing parameters in the payload.")

    # Check if username is present in the DB and is a registered user
    users = admin.get_users(current_app.scoped_session(), [username])
    users = users["users"]
    if len(users) == 0:
        raise NotFound("User {} not found!".format(username))
    elif len(users) > 1:
        raise InternalError("Too many user with the same username: {}. check the DB".format(username))

    # Check if policy is present in the DB
    policy = current_app.arborist.get_policy(policy_name)
    if policy is None:
        raise NotFound('Policy {} not found.'.format(policy_name))

    res = current_app.arborist.grant_user_policy(username, policy_name)
    if res is None:
        raise ArboristError(
            "Policy {} has not been assigned.".format(
                policy_name
            )
        )

    return jsonify(res)

@blueprint.route("/list_policies", methods=["GET"])
@admin_login_required
@enable_request_logging
def list_policies():
    """
    Return a list of all policies. Returns in JSON format
    """
    expand = request.args.get('expand', default = "")
    if(expand == "True"):
        expand = True
    elif(expand == ""):
        expand = False
    else:
        raise UserError("Expand parameter must be True or left blank")
    if(expand):
        res = current_app.arborist.list_policies(True)
    else:
        res = current_app.arborist.list_policies()
    return jsonify(res)

@blueprint.route("/arborist_user/<username>", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_arborist_user(username):
    """
    Return a list of all policies. Returns in JSON format
    """
    res = current_app.arborist.get_user(username)
    return res

@blueprint.route("/add_authz_all", methods=["POST"])
@admin_login_required
@enable_request_logging
def add_authz_all():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_authz_all`

    payload:
    `{
       "resource": {
          parent_path = '/services/',
          "name" = "amanuensis",
          "description" = "Amanuensis admin resource"
       },
       "role": {
          "id" = "amanuensis_admin"
          "description" = "can do admin work on project/data request"
          "permissions" = [
              {
                 "id": "amanuensis_admin_action", 
                 "action": {
                     "service": "amanuensis", 
                     "method": "*"}
                }
          ] 
       },
       "policy": {
          "id" = "services.amanuensis-admin",
          "description" = "admin access to amanunsis",
          "resource_paths" = [
            '/services/amanuensis'
          ],
          "role_ids" = [
            'amanuensis_admin'
          ]
       },
       "username" = "graglia01@gmail.com"
    
    }`
    """
    body = request.get_json()

    resource = body.get('resource', None)
    role = body.get('role', None)
    policy = body.get('policy', None)
    username = body.get('username', None)

    if resource is None or role is None or policy is None or username is None:
        raise UserError("There are some missing parameters in the payload.")


    # Check if username is present in the DB and is a registered user
    users = admin.get_users(current_app.scoped_session(), [username])
    if len(users) == 0:
        raise NotFound("User {} not found!".format(username))
    elif len(users) > 1:
        raise InternalError("Too many user with the same username: {}. check the DB".format(username))


    # parent_path = '/services/'
    parent_path = resource["parent_path"]
    resource_json = {}
    resource_json["name"] = resource["name"]
    resource_json["description"] = resource["description"]
    res = current_app.arborist.create_resource(parent_path, resource_json)
    if res is None:
        raise ArboristError(
            "Resource {} has not been created.".format(
                resource_json
            )
        )
    else:
        logger.info("Created resource {}".format(resource_json))


    role_json = {}
    role_json["id"] = role["id"]
    role_json["description"] = role["description"]
    role_json["permissions"] = role["permissions"]
    res = current_app.arborist.create_role(role_json)
    if res is None:
        raise ArboristError(
            "Role {} has not been created.".format(
                role_json
            )
        )
    else:
        logger.info("Created role {}".format(role_json))


    policy_json = {}
    policy_json["id"] = policy["id"]
    policy_json["description"] = policy["description"]
    policy_json["resource_paths"] = policy["resource_paths"]
    policy_json["role_ids"] = policy["role_ids"]
    res = current_app.arborist.create_policy(policy_json)
    if res is None:
        raise ArboristError(
            "Policy {} has not been createsd.".format(
                policy_json
            )
        )
    else:
        logger.info("Created role {}".format(policy_json))


    policy_name = policy["id"]
    res = current_app.arborist.grant_user_policy(username, policy_name)
    if res is None:
        raise ArboristError(
            "Policy {} has not been assigned.".format(
                policy_name
            )
        )

    return jsonify(res)

@blueprint.route("/revoke_permission", methods=["POST"])
@admin_login_required
@enable_request_logging
def revoke_permission():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/revoke_permission`

    payload:
    `{
        "username": "abc@gmail.com",
        "policy_names": ["policy_1", "policy_2", ...]
    }`
    """
    body = request.get_json()

    policy_names = body.get('policy_names', None)
    username = body.get('username', None)

    return jsonify(remove_permission(username, policy_names))


@blueprint.route("/add_document", methods=["POST"])
@admin_login_required
@enable_request_logging
def add_document():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_document`

    payload:
    `{
        "type": "privacy-policy",
        "version": 2,
        "name": "Privacy Policy",
        "raw": "https://github.com/chicagopcdc/Documents/blob/fda4a7c914173e29d13ab6249ded7bc9adea5674/governance/privacy_policy/privacy_notice.md",
        "formatted": "https://github.com/chicagopcdc/Documents/blob/81d60130308b6961c38097b6686a21f8be729a2c/governance/privacy_policy/PCDC-Privacy-Notice.pdf",
        "required": true
    }`
    """
    document_json = request.get_json()

    if document_json["type"] not in config["DOCUMENT_TYPES"]:
        raise UserError("Type {} not supported. Please talk with the developer team.".format(document_json["type"]))

    # TODO check input is in correct format

    document_schema = DocumentSchema()
    return jsonify(document_schema.dump(admin.add_document(current_app.scoped_session(), document_json)))


#### CLIENT ####
@blueprint.route("/add_policies_to_client", methods=["POST"])
@admin_login_required
@enable_request_logging
def add_policies_to_client():
    """
    Call this endpoint: `curl -XPOST -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" <hostname>/user/admin/add_policy_to_user`

    payload:
    `{
       "policy_names" = ["services.amanuensis-admin", "data_admin"],
       "client_id" = "akjsdhoadoadshaouhasod1!"
    }`
    """
    body = request.get_json()

    policy_names = body.get('policy_names', None)
    client_id = body.get('client_id', None)
    # TODO check that policy_names is in list format
    if client_id is None or policy_names is None or len(policy_names) < 1:
        raise UserError("There are some missing parameters in the payload.")

    # The arborist update_client endpoint is already checking if the client_id exists, if not it creates one. And it checks for the policies already as well
    try:
        current_app.arborist.update_client(
            client_id, policy_names
        )
    except ArboristError as e:
        self.logger.info(
            "not granting policies {} to client with id `{}`; {}".format(
                policy_names, client_id, str(e)
            )
        )
        raise ArboristError(
            "Error assigning policies to client {}".format(
                client_id
            )
        )

    return jsonify("Success")



#### PROJECTS ####
@blueprint.route("/projects/<projectname>", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_project(projectname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Get the information related to a project
    from the userdatamodel database
    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(admin.get_project_info(current_app.scoped_session(), projectname))


@blueprint.route("/projects", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_all_projects():
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Get the information related to a project
    from the userdatamodel database
    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(admin.get_all_projects(current_app.scoped_session()))


@blueprint.route("/projects/<projectname>", methods=["POST"])
@admin_login_required
@enable_request_logging
def create_project(projectname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a new project on the specified storage
    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    auth_id = request.get_json().get("auth_id")
    storage_accesses = request.get_json().get("storage_accesses", [])
    response = jsonify(
        admin.create_project(
            current_app.scoped_session(), projectname, auth_id, storage_accesses
        )
    )
    return response


@blueprint.route("/projects/<projectname>", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def delete_project(projectname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Remove project. No Buckets should be associated with it.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    response = jsonify(admin.delete_project(current_app.scoped_session(), projectname))
    return response


@blueprint.route("/groups/<groupname>/projects", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def remove_projects_from_group(groupname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user to group relationship in the database
    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    projects = request.get_json().get("projects", [])
    return jsonify(
        admin.remove_projects_from_group(
            current_app.scoped_session(), groupname, projects
        )
    )


@blueprint.route("/projects/<projectname>/groups", methods=["PUT"])
@admin_login_required
@enable_request_logging
def add_project_to_groups(projectname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user to group relationship in the database
    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    groups = request.get_json().get("groups", [])
    return jsonify(
        admin.add_project_to_groups(
            current_app.scoped_session(), username, groups=groups
        )
    )


@blueprint.route("/projects/<projectname>/bucket/<bucketname>", methods=["POST"])
@admin_login_required
@enable_request_logging
def create_bucket_in_project(projectname, bucketname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a bucket in the selected project.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    providername = request.get_json().get("provider")
    response = jsonify(
        admin.create_bucket_on_project(
            current_app.scoped_session(), projectname, bucketname, providername
        )
    )
    return response


@blueprint.route("/projects/<projectname>/bucket/<bucketname>", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def delete_bucket_from_project(projectname, bucketname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Delete a bucket from the selected project, both
    in the userdatamodel database and in the storage client
    associated with that bucket.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(
        admin.delete_bucket_on_project(
            current_app.scoped_session(), projectname, bucketname
        )
    )


@blueprint.route("/projects/<projectname>/bucket", methods=["GET"])
@admin_login_required
@enable_request_logging
def list_buckets_from_project(projectname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Retrieve the information regarding the buckets created within a project.

    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    response = jsonify(
        admin.list_buckets_on_project_by_name(current_app.scoped_session(), projectname)
    )
    return response


#### GROUPS ####


@blueprint.route("/groups/<groupname>", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_group_info(groupname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(admin.get_group_info(current_app.scoped_session(), groupname))


@blueprint.route("/groups", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_all_groups():
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(admin.get_all_groups(current_app.scoped_session()))


@blueprint.route("/groups/<groupname>/users", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_group_users(groupname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(admin.get_group_users(current_app.scoped_session(), groupname))


@blueprint.route("/groups", methods=["POST"])
@admin_login_required
@enable_request_logging
def create_group():
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    groupname = request.get_json().get("name")
    description = request.get_json().get("description")
    grp = admin.create_group(current_app.scoped_session(), groupname, description)
    if grp:
        response = admin.get_group_info(current_app.scoped_session(), groupname)
    else:
        response = {"result": "group creation failed"}
    response = jsonify(response)
    return response


@blueprint.route("/groups/<groupname>", methods=["PUT"])
@admin_login_required
@enable_request_logging
def update_group(groupname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    name = request.get_json().get("name", None)
    description = request.get_json().get("description", None)
    response = jsonify(
        admin.update_group(current_app.scoped_session(), groupname, description, name)
    )
    return response


@blueprint.route("/groups/<groupname>", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def delete_group(groupname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    response = jsonify(admin.delete_group(current_app.scoped_session(), groupname))
    return response


@blueprint.route("/groups/<groupname>/projects", methods=["PUT"])
@admin_login_required
@enable_request_logging
def add_projects_to_group(groupname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user to group relationship in the database
    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    projects = request.get_json().get("projects", [])
    response = jsonify(
        admin.add_projects_to_group(current_app.scoped_session(), groupname, projects)
    )
    return response


@blueprint.route("/groups/<groupname>/projects", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_group_projects(groupname):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a user to group relationship in the database
    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    values = admin.get_group_projects(current_app.scoped_session(), groupname)
    return jsonify({"projects": values})


#### CLOUD PROVIDER ####


@blueprint.route("/cloud_providers/<providername>", methods=["GET"])
@blueprint.route("/cloud_provider/<providername>", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_cloud_provider(providername):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Retriev the information related to a cloud provider
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    return jsonify(admin.get_provider(current_app.scoped_session(), providername))


@blueprint.route("/cloud_providers/<providername>", methods=["POST"])
@blueprint.route("/cloud_provider/<providername>", methods=["POST"])
@admin_login_required
@enable_request_logging
def create_cloud_provider(providername):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Create a cloud provider.
    Returns a json object
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    backend_name = request.get_json().get("backend")
    service_name = request.get_json().get("service")
    response = jsonify(
        admin.create_provider(
            current_app.scoped_session(),
            providername,
            backend=backend_name,
            service=service_name,
        )
    )
    return response


@blueprint.route("/cloud_providers/<providername>", methods=["DELETE"])
@blueprint.route("/cloud_provider/<providername>", methods=["DELETE"])
@admin_login_required
@enable_request_logging
def delete_cloud_provider(providername):
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    Deletes a cloud provider from the userdatamodel
    All projects associated with it should be deassociated
    or removed.
    Returns a json object.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    response = jsonify(
        admin.delete_provider(current_app.scoped_session(), providername)
    )
    return response


@blueprint.route("/register", methods=["GET"])
@admin_login_required
@enable_request_logging
def get_registered_users():
    """
    DEPRECATED: This endpoint is deprecated and will be removed in a future release.

    - List registration info for every user for which there exists registration info.
    - Endpoint accessible to admins only.
    - Response json structure is provisional.
    """
    logger.warning(
        f"Deprecated endpoint accessed: {request.path}. This endpoint is deprecated and will be removed in a future release."
    )
    registered_users = (
        current_app.scoped_session()
        .query(User)
        .filter(User.additional_info["registration_info"] != "{}")
        .all()
    )
    registration_info_list = {
        u.username: u.additional_info["registration_info"] for u in registered_users
    }
    return registration_info_list
