"""
Blueprints for administation of the userdatamodel
database and the storage solutions. Operations here
assume the underlying operations in the interface will
maintain coherence between both systems
"""
from flask import (
    request,
    jsonify,
    Blueprint,
)

from fence.auth import (
    login_required,
    admin_required,
)

from fence.resources.user import (
    get_info_by_username,
)

from fence.resources.admin import (
    get_project_by_name,
    delete_project_by_name,
    get_provider_by_name,
    create_project_by_name,
    create_provider_by_name,
    delete_provider_by_name,
    create_user_by_username,
    delete_user_by_username,
    create_bucket_on_project_by_name,
    delete_bucket_on_project_by_name,
    list_buckets_on_project_by_name,
)


blueprint = Blueprint('admin', __name__)

@blueprint.route('/user/<username>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_user(username):
    """
    Get the information of a user from our
    userdatamodel database.
    Returns a json object
    """
    return get_info_by_username(username)

@blueprint.route('/user/<username>', methods=['PUT'])
@login_required({'admin'})
@admin_required
def create_user(username):
    """
    Create a user on the userdatamodel database
    and the storage solution associated with
    the project. Then add access to the buckets
    associated with the project.
    Returns a json object
    """
    projects = request.get_json().get('projects')
    return jsonify(create_user_by_username(username, projects))

@blueprint.route('/user/<username>', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def delete_user(username):
    """
    Remove the user from the userdatamodel database
    and all associated storage solutions.
    Returns json object
    """
    return jsonify(delete_user_by_username(username))

@blueprint.route('/project/<projectname>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_project(projectname):
    """
    Get the information related to a project
    from the userdatamodel database
    Returns a json object
    """
    return jsonify(get_project_by_name(projectname))

@blueprint.route('/project/<projectname>', methods=['PUT'])
@login_required({'admin'})
@admin_required
def create_project(projectname):
    """
    Create a new project on the specified storage
    Returns a json object
    """
    auth_id = request.get_json().get('auth_id')
    storage_accesses = request.get_json().get('storage_accesses')
    return jsonify(
        create_project_by_name(
            projectname,
            auth_id,
            storage_accesses
        )
    )

@blueprint.route('/project/<projectname>', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def delete_project(projectname):
    """
    Remove project. No Buckets should be associated with it.
    Returns a json object.
    """
    return jsonify(delete_project_by_name(projectname))

@blueprint.route('/cloud_provider/<providername>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_cloud_provider(providername):
    """
    Retriev the information related to a cloud provider
    Returns a json object.
    """
    return jsonify(get_provider_by_name(providername))

@blueprint.route('/cloud_provider/<providername>', methods=['PUT'])
@login_required({'admin'})
@admin_required
def create_cloud_provider(providername):
    """
    Create a cloud provider.
    Returns a json object
    """
    backend_name = request.get_json().get('backend')
    service_name = request.get_json().get('service')
    return jsonify(
        create_provider_by_name(
            providername,
            backend=backend_name,
            service=service_name
        )
    )

@blueprint.route('/cloud_provider/<providername>', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def delete_cloud_provider(providername):
    """
    Deletes a cloud provider from the userdatamodel
    All projects associated with it should be deassociated
    or removed.
    Returns a json object.
    """
    return jsonify(delete_provider_by_name(providername))

@blueprint.route('/project/<projectname>/bucket/<bucketname>', methods=['PUT'])
@login_required({'admin'})
@admin_required
def create_bucket_in_project(projectname, bucketname):
    """
    Create a bucket in the selected project.
    Returns a json object.
    """
    providername = request.get_json().get('provider')
    return jsonify(
        create_bucket_on_project_by_name(
            projectname,
            bucketname,
            providername
        )
    )

@blueprint.route(
    '/project/<projectname>/bucket/<bucketname>',
    methods=['DELETE']
)
@login_required({'admin'})
@admin_required
def delete_bucket_from_project(projectname, bucketname):
    """
    Delete a bucket from the selected project, both
    in the userdatamodel database and in the storage client
    associated with that bucket.
    Returns a json object.
    """
    return jsonify(delete_bucket_on_project_by_name(projectname, bucketname))

@blueprint.route('/project/<projectname>/bucket', methods=['GET'])
@login_required({'admin'})
@admin_required
def list_buckets_from_project(projectname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(list_buckets_on_project_by_name(projectname))
