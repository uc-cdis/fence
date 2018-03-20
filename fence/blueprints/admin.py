import flask


from fence.auth import require_auth, require_admin
from fence.errors import UserError
from fence.resources.user import get_info_by_username, update_user_resource

blueprint = flask.Blueprint('admin', __name__)


@blueprint.route('/user/<username>', methods=['GET'])
@require_admin
@require_auth(aud={'openid'}, purpose='access')
def get_user(username):
    return get_info_by_username(username)


@blueprint.route('/user/<username>', methods=['PUT'])
@require_admin
@require_auth(aud={'openid'}, purpose='access')
def update_user(username):
    resource = flask.request.get_json().get('resource')
    if not resource:
        raise UserError('Please provide resource to be granted')
    if resource not in ['compute', 'storage']:
        raise UserError('Resource {} is invalid'.format(resource))
    return update_user_resource(username, resource)
