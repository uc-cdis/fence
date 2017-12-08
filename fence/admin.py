import flask
from errors import UserError
from flask import request
from auth import login_required
from resources.user import get_info_by_username, update_user_resource

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
