import flask
from fence.errors import UserError
from flask import request
from fence.auth import login_required
from fence.resources.group import get_info_by_group_id, get_all_groups_info
from fence.resources.user import get_info_by_username, update_user_resource

blueprint = flask.Blueprint('admin', __name__)


@blueprint.route('/user/<username>', methods=['GET'])
@login_required({'admin'})
def get_user(username):
    return get_info_by_username(username)


@blueprint.route('/user/<username>', methods=['PUT'])
@login_required({'admin'})
def update_user(username):
    resource = request.get_json().get('resource')
    if not resource:
        raise UserError('Please provide resource to be granted')
    if resource not in ['compute', 'storage']:
        raise UserError('Resource {} is invalid'.format(resource))
    return update_user_resource(username, resource)


@blueprint.route('/groups/<id>', methods=['GET'])
@login_required({'admin'})
def get_stupid_group(id):
    return get_info_by_group_id(id)


@blueprint.route('/groups', methods=['GET'])
@login_required({'admin'})
def get_all_groups(id):
    return get_all_groups_info(id)