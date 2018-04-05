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
    current_app,
)

from fence.auth import (
    login_required,
    admin_required,
)


from fence.resources import admin as adm
from flask_sqlalchemy_session import current_session

blueprint = Blueprint('admin', __name__)


#### USERS ####


@blueprint.route('/user/<username>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_user(username):
    """
    Get the information of a user from our
    userdatamodel database.
    Returns a json object
    """
    current_app.logger.debug("get_user:\n\tname:  {0}".format(
        username))
    return jsonify(adm.get_user_info(current_session, username.upper()))


@blueprint.route('/user', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_all_users():
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    current_app.logger.debug("get_all_users")
    return jsonify(adm.get_all_users(current_session))


@blueprint.route('/user', methods=['POST'])
@login_required({'admin'})
@admin_required
def create_user():
    """
    Create a user on the userdatamodel database
    Returns a json object
    """
    username = request.get_json().get('name',None)
    role = request.get_json().get('role',None)
    email = request.get_json().get('email',None)
    current_app.logger.debug(
        ("create_user:\n\tname: {0}\n\t"
        "role: {1}\n\temail: {2}").format(
            username, role, email))        
    response = jsonify(adm.create_user(current_session, username.upper, role, email))
    return response


@blueprint.route('/user/<username>', methods=['PUT'])
@login_required({'admin'})
@admin_required
def update_user(username):
    """
    Create a user on the userdatamodel database
    Returns a json object
    """
    name = request.get_json().get('name', None)
    role = request.get_json().get('role',None)
    email = request.get_json().get('email',None)
    current_app.logger.debug(
        ("update_user:\n\tname: {0}\n\t"
        "role: {1}\n\temail: {2}").format(
            username, role, email))        
    response = jsonify(adm.update_user(current_session, username.upper(), role, email, name))
    return response

@blueprint.route('/user/<username>', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def delete_user(username):
    """
    Remove the user from the userdatamodel database
    and all associated storage solutions.
    Returns json object
    """
    current_app.logger.debug("delete_user:\n\tname:  {0}".format(
        username))
    response = jsonify(adm.delete_user(current_session, username.upper()))
    return response

@blueprint.route('/user/<username>/groups', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_user_groups(username):
    """
    Get the information of a user from our
    userdatamodel database.
    Returns a json object
    """
    current_app.logger.debug("get_user_groups:\n\tname:  {0}".format(
        username))
    return jsonify(adm.get_user_groups(current_session, username.upper()))


@blueprint.route('/user/<username>/groups', methods=['PUT'])
@login_required({'admin'})
@admin_required
def add_user_to_groups(username):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    groups = request.get_json().get('groups', [])
    current_app.logger.debug("add_user_to_groups:\n\tname:  {0}\n\tgroups: {1}".format(
        username, str(groups)))
    response = jsonify(adm.add_user_to_groups(current_session, username.upper(), groups=groups))
    return response


@blueprint.route('/user/<username>/groups', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def remove_user_from_groups(username):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    groups = request.get_json().get('groups', [])
    current_app.logger.debug("remove_user_from_groups:\n\tname:  {0}\n\tgroups: {1}".format(
        username, str(groups)))
    response = jsonify(adm.remove_user_from_groups(current_session, username.upper(), groups=groups))
    return response


@blueprint.route('/user/<username>/projects', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def remove_user_from_projects(username):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    projects = request.get_json().get('projects', [])
    current_app.logger.debug("remove_user_from_projects:\n\tname:  {0}\n\projects: {1}".format(
        username, str(projects)))
    response = jsonify(adm.remove_user_from_projects(current_session, username.upper(), projects))
    return response

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
    current_app.logger.debug("add_user_from_projects:\n\tname:  {0}\n\projects: {1}".format(
        username, str(projects)))
    response = jsonify(adm.add_user_to_projects(current_session, username.upper(), projects=projects))
    return response


#### PROJECTS ####


@blueprint.route('/projects/<projectname>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_project(projectname):
    """
    Get the information related to a project
    from the userdatamodel database
    Returns a json object
    """
    current_app.logger.debug("get_project")
    return jsonify(adm.get_project_info(current_session, projectname))


@blueprint.route('/projects', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_all_projects():
    """
    Get the information related to a project
    from the userdatamodel database
    Returns a json object
    """
    current_app.logger.debug("get_all_projects")
    return jsonify(adm.get_all_projects(current_session))


@blueprint.route('/projects/<projectname>', methods=['POST'])
@login_required({'admin'})
@admin_required
def create_project(projectname):
    """
    Create a new project on the specified storage
    Returns a json object
    """
    auth_id = request.get_json().get('auth_id')
    storage_accesses = request.get_json().get('storage_accesses',[])
    current_app.logger.debug("create_project:\n\tname:  {0}\n\auth_id: {1}\n\tstorage_access: {2}".format(
        projectname, auth_id, str(storage_accesses)))
    response = jsonify(
        adm.create_project(
            current_session,
            projectname,
            auth_id,
            storage_accesses
        )
    )
    return response


@blueprint.route('/projects/<projectname>', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def delete_project(projectname):
    """
    Remove project. No Buckets should be associated with it.
    Returns a json object.
    """
    current_app.logger.debug("delete_project:\n\tname:  {0}".format(
        projectname))
    response = jsonify(adm.delete_project(current_session, projectname))
    return response

@blueprint.route('/groups/<groupname>/projects', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def remove_projects_from_group(groupname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    projects = request.get_json().get('projects', [])
    current_app.logger.debug("delete_projects_from_group:\n\tgroup:  {0}".format(
        groupname))
    response = jsonify(adm.remove_projects_from_group(current_session,groupname, projects))
    return response

@blueprint.route('/projects/<projectname>/groups', methods=['PUT'])
@login_required({'admin'})
@admin_required
def add_project_to_groups(projectname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    groups = request.get_json().get('groups', [])
    response = jsonify(adm.add_project_to_groups(current_session, username.upper(), groups=groups))
    return response

@blueprint.route('/projects/<projectname>/bucket/<bucketname>', methods=['POST'])
@login_required({'admin'})
@admin_required
def create_bucket_in_project(projectname, bucketname):
    """
    Create a bucket in the selected project.
    Returns a json object.
    """
    providername = request.get_json().get('provider')
    response = jsonify(
        adm.create_bucket_on_project(
            current_session,
            projectname,
            bucketname,
            providername
        )
    )
    return response

@blueprint.route(
    '/projects/<projectname>/bucket/<bucketname>',
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
    return jsonify(adm.delete_bucket_on_project(current_session, projectname, bucketname))

@blueprint.route('/projects/<projectname>/bucket', methods=['GET'])
@login_required({'admin'})
@admin_required
def list_buckets_from_project(projectname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    response = jsonify(adm.list_buckets_on_project_by_name(current_session, projectname))
    return response


#### GROUPS ####


@blueprint.route('/groups/<groupname>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_group_info(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(adm.get_group_info(current_session, groupname))


@blueprint.route('/groups', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_all_groups():
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(adm.get_all_groups(current_session))


@blueprint.route('/groups/<groupname>/users', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_group_users(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    return jsonify(adm.get_group_users(current_session, groupname))


@blueprint.route('/groups', methods=['POST'])
@login_required({'admin'})
@admin_required
def create_group():
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    groupname = request.get_json().get('name')
    description = request.get_json().get('description')
    grp = adm.create_group(current_session, groupname, description)
    if grp:
        response = adm.get_group_info(current_session, groupname)
    else:
        response = {'result': 'group creation failed'}
    response = jsonify(response)
    return response


@blueprint.route('/groups/<groupname>', methods=['PUT'])
@login_required({'admin'})
@admin_required
def update_group(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    name = request.get_json().get('name', None)
    description = request.get_json().get('description', None)
    response = jsonify(adm.update_group(current_session, groupname, description, name))
    return response
 

@blueprint.route('/groups/<groupname>', methods=['DELETE'])
@login_required({'admin'})
@admin_required
def delete_group(groupname):
    """
    Retrieve the information regarding the
    buckets created within a project.
    Returns a json object.
    """
    response = jsonify(adm.delete_group(current_session, groupname))
    return response


@blueprint.route('/groups/<groupname>/projects', methods=['PUT'])
@login_required({'admin'})
@admin_required
def add_projects_to_group(groupname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    projects = request.get_json().get('projects', [])
    response = jsonify(adm.add_projects_to_group(current_session,groupname, projects))
    return response


@blueprint.route('/groups/<groupname>/projects', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_group_projects(groupname):
    """
    Create a user to group relationship in the database
    Returns a json object
    """
    values = adm.get_group_projects(current_session,groupname)
    return jsonify({"projects": values })



#### CLOUD PROVIDER ####


@blueprint.route('/cloud_provider/<providername>', methods=['GET'])
@login_required({'admin'})
@admin_required
def get_cloud_provider(providername):
    """
    Retriev the information related to a cloud provider
    Returns a json object.
    """
    return jsonify(adm.get_provider(current_session, providername))

@blueprint.route('/cloud_provider/<providername>', methods=['POST'])
@login_required({'admin'})
@admin_required
def create_cloud_provider(providername):
    """
    Create a cloud provider.
    Returns a json object
    """
    backend_name = request.get_json().get('backend')
    service_name = request.get_json().get('service')
    response = jsonify(
        adm.create_provider(
            current_session,
            providername,
            backend=backend_name,
            service=service_name
        )
    )
    return response


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
    response = jsonify(adm.delete_provider(current_session, providername))
    return response
