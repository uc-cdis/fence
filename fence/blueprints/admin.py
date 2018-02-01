import flask
from flask import request
from fence.auth import login_required
import fence.resources.group as gp
import fence.resources.user as usr
from fence.errors import UserError

blueprint = flask.Blueprint('admin', __name__)


@blueprint.route('/user/<username>', methods=['GET'])
@login_required({'admin'})
def get_user(username):
    """
    Get user name
    :param username:
    :return:
    """
    return usr.get_info_by_username(username)


@blueprint.route('/user/<username>', methods=['PUT'])
@login_required({'admin'})
def update_user(username):
    """
    Update user name
    :param username:
    :return:
    """
    resource = request.get_json().get('resource')
    if not resource:
        raise UserError('Please provide resource to be granted')
    if resource not in ['compute', 'storage']:
        raise UserError('Resource {} is invalid'.format(resource))
    return usr.update_user_resource(username, resource)


@blueprint.route('/groups/<group_id>', methods=['GET'])
@login_required({'admin'})
def get_group_by_id(group_id):
    """
    Get Group by ID
    :param: group_id:
    :return:
    """
    return gp.get_group_id(group_id)


@blueprint.route('/groups', methods=['GET'])
@login_required({'admin'})
def get_all_groups():
    """
    Get all groups
    :return: List of groups [id, name, and lead_id]
    """
    return gp.get_all_groups_info()


@blueprint.route('/groups/projects/<group_id>', methods=['GET'])
@login_required({'admin'})
def get_projects_by_group_id(group_id):
    """
    Return all projects associated with a group ID
    :param group_id: List of projects [project_id, privilege]
    :return:
    """
    return gp.get_projects_by_group(group_id)
