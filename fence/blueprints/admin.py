"""
Blueprints for administation of the userdatamodel database and the storage
solutions. Operations here assume the underlying operations in the interface
will maintain coherence between both systems.
"""

import functools

from flask import request, jsonify, Blueprint, current_app
from flask import current_app

from cdislogging import get_logger

from fence.auth import admin_login_required
from fence.resources.audit.utils import enable_request_logging
from fence.resources import admin
from fence.models import User


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
