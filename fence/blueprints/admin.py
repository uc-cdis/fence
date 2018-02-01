import flask
from fence.errors import UserError
from flask import request
from fence.auth import login_required
import fence.resources.group as gp
import fence.resources.user as usr

blueprint = flask.Blueprint('admin', __name__)


@blueprint.route('/user/<username>', methods=['GET'])
@login_required({'admin'})
def get_user(username):
    return usr.get_info_by_username(username)


@blueprint.route('/user/<username>', methods=['PUT'])
@login_required({'admin'})
def update_user(username):
    resource = request.get_json().get('resource')
    if not resource:
        raise UserError('Please provide resource to be granted')
    if resource not in ['compute', 'storage']:
        raise UserError('Resource {} is invalid'.format(resource))
    return usr.update_user_resource(username, resource)


@blueprint.route('/groups/<id>', methods=['GET'])
@login_required({'admin'})
def get_group_by_id(id):
    return gp.get_group_id(id)


@blueprint.route('/groups', methods=['GET'])
@login_required({'admin'})
def get_all_groups():
    return gp.get_all_groups_info()


@blueprint.route('/groups/projects/<group_id>', methods=['GET'])
@login_required({'admin'})
def get_projects_by_group_id(group_id):
    return gp.get_projects_by_group(group_id)