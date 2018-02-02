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

from fence.resources import admin as adm


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
    Returns a json object
    """
    return jsonify(adm.create_user(username))

@blueprint.route('/user/<username>/groups', methods=['PUT'])
@login_required({'admin'})
@admin_required
def add_user_to_groups(username):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    groups = request.get_json().get('groups', [])
    return jsonify(adm.add_user_to_groups(username, groups=groups))


@blueprint.route('/user/<username>/groups', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def remove_user_from_groups(username):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    groups = request.get_json().get('groups', [])
    return jsonify(adm.remove_user_from_groups(username, groups=groups))

@blueprint.route('/groups/<groupname>/projects', methods=['PUT'])
@login_required({'admin'})
@admin_required
def add_projects_to_group(groupname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    projects = request.get_json().get('projects', [])
    return jsonify(adm.add_projects_to_group(groupname, projects))


@blueprint.route('/groups/<groupname>/projects', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def remove_projects_from_group(groupname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    projects = request.get_json().get('projects', [])
    return jsonify(adm.remove_projects_from_group(groupname, projects))


@blueprint.route('/project/<projectname>/groups', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def add_project_to_groups(projectname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    groups = request.get_json().get('groups', [])
    return jsonify(adm.add_user_to_projects(username, groups=groups))

@blueprint.route('/project/<projectname>/groups', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def remove_project_to_groups(projectname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    groups = request.get_json().get('groups', [])
    return jsonify(adm.remove_user_from_projects(username, groups=groups))


@blueprint.route('/user/<username>/projects', methods=['PUT'])
@login_required({'admin'})
@admin_required
def add_user_to_projects(username):
    """
    Create a user to project relationship on the database
    and add the access to the the object store associated with it
    Returns a json object
    """
    projects = request.get_json().get('projects', [])
    return jsonify(adm.add_user_to_projects(username, projects=projects))


@blueprint.route('/user/<username>', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def delete_user(username):
    """
    Remove the user from the userdatamodel database
    and all associated storage solutions.
    Returns json object
    """
    return jsonify(adm.delete_user(username))

@blueprint.route('/project/<projectname>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_project(projectname):
    """
    Get the information related to a project
    from the userdatamodel database
    Returns a json object
    """
    return jsonify(adm.get_project_by_name(projectname))

@blueprint.route('/project/<projectname>', methods=['PUT'])
@login_required({'admin'})
@admin_required
def create_project(projectname):
    """
    Create a new project on the specified storage
    Returns a json object
    """
    auth_id = request.get_json().get('auth_id')
    storage_accesses = request.get_json().get('storage_accesses',[])
    return jsonify(
        adm.create_project_by_name(
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
    return jsonify(adm.delete_project_by_name(projectname))

@blueprint.route('/cloud_provider/<providername>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_cloud_provider(providername):
    """
    Retriev the information related to a cloud provider
    Returns a json object.
    """
    return jsonify(adm.get_provider_by_name(providername))

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
        adm.create_provider_by_name(
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
    return jsonify(adm.delete_provider_by_name(providername))

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
        adm.create_bucket_on_project_by_name(
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
    return jsonify(adm.delete_bucket_on_project_by_name(projectname, bucketname))

@blueprint.route('/project/<projectname>/bucket', methods=['GET'])
@login_required({'admin'})
@admin_required
def list_buckets_from_project(projectname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(adm.list_buckets_on_project_by_name(projectname))

@blueprint.route('/groups', methods=['PUT'])
@login_required({'admin'})
@admin_required
def create_group():
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    groupname = request.get_json().get('name')
    grp = adm.create_group(groupname)
    if grp:
        response = {'result': 'group creation successful'}
    else:
        response = {'result': 'group creation failed'}
    return jsonify(response)

@blueprint.route('/groups/<groupname>', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def delete_group(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(adm.delete_group(groupname))
