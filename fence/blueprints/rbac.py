"""
Provide an interface in front of the engine for role-based access control
(RBAC).

TODO: instead of ``admin_login_required``, these routes should check with
arborist to see if the user has roles allowing them to use these endpoints.
"""

import flask
from flask_sqlalchemy_session import current_session

from fence.auth import admin_login_required
from fence.errors import NotFound
from fence.models import User


blueprint = flask.Blueprint('role', __name__)


def _get_user(user_id):
    """
    Args:
        user_id (str)

    Return:
        fence.models.User
    """
    with flask.current_app.db.session as session:
        user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise NotFound('no user exists with ID: {}'.format(user_id))
    return user


@blueprint.route('/role/', methods=['GET'])
@admin_login_required
def list_roles():
    """
    List all the existing roles.
    """
    return flask.jsonify(flask.current_app.arborist.list_roles())


@blueprint.route('/role/', methods=['POST'])
@admin_login_required
def create_role():
    """
    Create a new role.
    """
    data = flask.request.get_json()
    return flask.jsonify(flask.current_app.arborist.create_role(data))


@blueprint.route('/role/<role_id>', methods=['GET', 'DELETE', 'PATCH', 'PUT'])
@admin_login_required
def role_operation(role_id):
    """
    Handle read, update, append, and delete operations on an existing role.
    """
    return flask.jsonify(flask.current_app.arborist.role_request(
        role_id, method=flask.request.method, json=flask.request.get_json()
    ))


@blueprint.route('/resource/', methods=['GET'])
@admin_login_required
def list_resources():
    """
    List all the existing resources.
    """
    return flask.jsonify(flask.current_app.arborist.list_resources())


@blueprint.route('/resource/', methods=['POST'])
@admin_login_required
def create_resource():
    """
    Create a new resource.
    """
    data = flask.request.get_json()
    return flask.jsonify(flask.current_app.arborist.create_resource(data))


@blueprint.route(
    '/resource/<resource_id>',
    methods=['GET', 'DELETE', 'PATCH', 'PUT'],
)
@admin_login_required
def resource_operation(resource_id):
    """
    Handle read, update, append, and delete operations on an existing resource.
    """
    return flask.jsonify(flask.current_app.arborist.resource_request(
        resource_id, method=flask.request.method, json=flask.request.get_json()
    ))


@blueprint.route('/policy/', methods=['GET'])
@admin_login_required
def list_policies():
    """
    List all the existing policies.

    Example:

        {
            "policies": [

            ]
        }
    """
    return flask.jsonify(flask.current_app.arborist.list_policies())


@blueprint.route('/user/<user_id>/policies/', methods=['GET'])
@admin_login_required
def list_user_policies(user_id):
    """
    List the policies that this user has access to.

    Example:

        {
            "policies": [
                "
            ]
        }
    """
    user = _get_user(user_id)
    policy_ids = [policy.ID for policy in user.policies]
    return flask.jsonify({'policies': policy_ids})


@blueprint.route('/user/<user_id>/policies/', methods=['POST'])
def grant_policy_to_user(user_id):
    """
    Grant additional policies to a user.
    """
    user = _get_user(user_id)
