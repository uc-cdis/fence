"""
Provide an interface in front of the engine for role-based access control
(RBAC).

TODO (rudyardrichter):
instead of ``admin_login_required``, these routes should check with arborist to
see if the user has roles allowing them to use these endpoints.
"""

import flask

from fence.auth import admin_login_required
from fence.errors import NotFound, UserError
from fence.models import Policy, User


blueprint = flask.Blueprint('rbac', __name__)


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


def lookup_policies(policy_ids):
    """
    Look up the list of policies from the database.

    Requires flask application context.

    Args:
        policy_ids (List[str]): list of IDs for the policies to return

    Return:
        List[fence.model.Policy]: list of policy models

    Raises:
        - ValueError: if any of the policy IDs do not correspond to an existing
          policy
    """
    policies = []
    with flask.current_app.db.session as session:
        for policy_id in policy_ids:
            policy = session.query(Policy).filter_by(ID=policy_id).first()
            if not policy:
                raise NotFound(
                    'policy not registered in fence: {}'
                    .format(policy_id)
                )
            policies.append(policy)
    return policies


def _validate_policy_ids(policy_ids):
    """
    Check some user-inputted policy IDs which should correspond to roles in
    arborist.

    Check:
        - Policies argument is there
        - All the listed policies are valid
            - Contain correct fields
            - Actually exist in arborist

    Args:
        policy_ids (List[str]): list of policy IDs

    Return:
        List[str]: the same policy_ids, if they validated

    Raises:
        UserError: if the policy ID list fails to validate
    """
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
    return policy_ids


def _list_all_policies(session):
    return session.query(Policy).all()


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
    with flask.current_app.db.session as session:
        policies = _list_all_policies(session)
    return flask.jsonify({'policies': policies})


@blueprint.route('/user/<user_id>/policies/', methods=['GET'])
@admin_login_required
def list_user_policies(user_id):
    """
    List the policies that this user has access to.

    Output will be in the same format as the ``/policy/`` endpoint, but
    only containing policies this user has access to.
    """
    user = _get_user(user_id)
    policy_ids = [policy.id for policy in user.policies]
    return flask.jsonify({'policies': policy_ids})


@blueprint.route('/user/<user_id>/policies/', methods=['POST'])
@admin_login_required
def grant_policy_to_user(user_id):
    """
    Grant additional policies to a user.
    """
    policy_ids = _validate_policy_ids(flask.request.get_json().get('policies'))

    with flask.current_app.db.session as session:
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            raise NotFound('no user exists with ID: {}'.format(user_id))
        policies = lookup_policies(policy_ids)
        user.policies.extend(policies)
        session.commit()

    return '', 204


@blueprint.route('/user/<user_id>/policies/', methods=['PUT'])
@admin_login_required
def replace_user_policies(user_id):
    """
    Overwrite the user's existing policies and replace them with the ones
    provided in the request.
    """
    policy_ids = _validate_policy_ids(flask.request.get_json().get('policies'))

    with flask.current_app.db.session as session:
        user = _get_user(user_id)
        policies = lookup_policies(policy_ids)
        user.policies = policies
        session.commit()

    return '', 204


@blueprint.route('/user/<user_id>/policies/', methods=['DELETE'])
@admin_login_required
def revoke_user_policies(user_id):
    """
    Revoke all the policies which this user has access to.
    """
    with flask.current_app.db.session as session:
        user = _get_user(user_id)
        # Set user's policies to empty list.
        user.policies = []
        session.commit()
    return '', 204
