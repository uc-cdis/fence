"""
Provide an interface in front of the engine for role-based access control
(RBAC).

TODO (rudyardrichter):
instead of ``admin_login_required``, these routes should check with arborist to
see if the user has roles allowing them to use these endpoints.
"""

import flask

from fence.auth import admin_login_required
from fence.errors import InternalError, NotFound, UserError
from fence.models import Policy, User


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


@blueprint.route('/policy/', methods=['GET'])
@admin_login_required
def list_policies():
    """
    List all the existing policies.

    Example output JSON:

        {
            "policies": [
                "policy-abc",
                "policy-xyz"
            ]
        }
    """
    return flask.jsonify(flask.current_app.arborist.list_policies())


@blueprint.route('/policy/', methods=['POST'])
@admin_login_required
def create_policies():
    """
    Create new policies in arborist and add the models to the database.

    Expected input JSON:

    Example output JSON:

        {
            "created": [
                {
                    "id": "foo",
                    "role_ids": ["role-a", "role-b"],
                    "resource_paths": ["/some/resource/1", "/some/resource/2"]
                }
            ]
        }
    """
    return flask.current_app.arborist.create_policies(flask.request.get_json())


@blueprint.route('/user/<user_id>/policies/', methods=['GET'])
@admin_login_required
def list_user_policies(user_id):
    """
    List the policies that this user has access to.

    Output will be in the same format as the ``/policy/`` endpoint, but
    only containing policies this user has access to.
    """
    user = _get_user(user_id)
    policy_ids = [policy.ID for policy in user.policies]
    return flask.jsonify({'policies': policy_ids})


@blueprint.route('/user/<user_id>/policies/', methods=['POST'])
@admin_login_required
def grant_policy_to_user(user_id):
    """
    Grant additional policies to a user.
    """
    # Input validation:
    #     - Policies argument is there
    #     - All the listed policies are valid
    #         - Contain correct fields
    #         - Actually exist in arborist
    policy_ids = flask.request.get_json().get('policies')
    if not policy_ids:
        raise UserError('JSON missing required value `policies`')
    missing_policies = flask.current_app.arborist.policies_not_exist(
        policy_ids
    )
    if any(missing_policies):
        raise UserError(
            'policies with these IDs do not exist in arborist: {}'
            .format(missing_policies)
        )

    with flask.current_app.db.session as session:
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            raise NotFound('no user exists with ID: {}'.format(user_id))

        policies_to_grant = []
        for policy_id in policy_ids:
            policy = session.query(Policy).filter_by(ID=policy_id).first()
            if not policy:
                raise InternalError(
                    'policy not registered in fence: {}'
                    .format(policy_id)
                )
            policies_to_grant.append(policy)

        for policy in policies_to_grant:
            user.policies.append(policy)

    return flask.jsonify({'granted': policy_ids})
