"""
Provide an interface in front of the engine for role-based access control
(RBAC).

TODO: instead of ``admin_login_required``, these routes should check with
arborist to see if the user has roles allowing them to use these endpoints.
"""

import flask
from flask_sqlalchemy_session import current_session

from fence.auth import admin_login_required
from fence.models import User


blueprint = flask.Blueprint('role', __name__)


@blueprint.route('/role/', methods=['GET'])
@admin_login_required
def list_roles():
    """List all the existing roles."""
    return flask.jsonify(flask.current_app.arborist.list_roles())


@blueprint.route('/role/', methods=['POST'])
@admin_login_required
def create_role():
    """Create a new role."""
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


@blueprint.route('/user/<user_id>/roles/', methods=['GET'])
@admin_login_required
def list_user_roles(user_id):
    """
    List the roles that this user has.
    """
    user = current_session.query(User).filter(User.id == user_id).first()
