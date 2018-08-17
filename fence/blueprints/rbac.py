"""
Provide an interface in front of the engine for role-based access control
(RBAC).

TODO (rudyardrichter):
instead of ``login_required``, these routes should check with arborist to see
if the user has roles allowing them to use these endpoints.
"""

import flask

from fence.auth import login_required
from fence.errors import NotFound, UserError
from fence.models import Policy, User


blueprint = flask.Blueprint('rbac', __name__)


@blueprint.route('/policies/', methods=['GET'])
@login_required({'admin'})
def list_policies():
    """
    List all the existing policies. (In fence, not arborist.)

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
    return flask.jsonify({'policies': [policy.id for policy in policies]})


@blueprint.route('/policies/', methods=['POST'])
@login_required({'admin'})
def create_policy():
    """
    Create new policies in the fence database, *without* granting it to any
    users. The policy *must* already exist in arborist, otherwise this
    operation will fail.
    """
    policy_ids = flask.request.get_json().get('policies', [])
    missing = flask.current_app.arborist.policies_not_exist(policy_ids)
    if missing:
        raise ValueError(
            'the following policies do not exist in arborist: '
            + ', '.join(missing)
        )
    with flask.current_app.db.session as session:
        for policy_id in policy_ids:
            session.add(Policy(id=policy_id))
    return flask.jsonify({'created': policy_ids}), 201


@blueprint.route('/policies/<policy_id>', methods=['DELETE'])
@login_required({'admin'})
def delete_policy(policy_id):
    """
    Delete a policy from the database.

    Fence should not include policies in tokens which are not understood by
    arborist, so when policies are removed from arborist, arborist (or arborist
    maintainers) can use this endpoint to remove the same policy from fence.
    """
    with flask.current_app.db.session as session:
        policy_to_delete = (
            session
            .query(Policy)
            .filter(Policy.id == policy_id)
            .first()
        )
        session.delete(policy_to_delete)
    return '', 204


@blueprint.route('/user/<user_id>/policies/', methods=['GET'])
@login_required({'admin'})
def list_user_policies(user_id):
    """
    List the policies that this user has access to.

    Output will be in the same format as the ``/policy/`` endpoint, but
    only containing policies this user has access to.
    """
    return flask.jsonify({'policies': _get_user_policy_ids(user_id)})


@blueprint.route('/user/<user_id>/policies/', methods=['POST'])
@login_required({'admin'})
def grant_policy_to_user(user_id):
    """
    Grant additional policies to a user.
    """
    policy_ids = _validate_policy_ids(flask.request.get_json().get('policies'))

    with flask.current_app.db.session as session:
        policies = lookup_policies(policy_ids)
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError('no user exists with ID: {}'.format(user_id))
        user.policies.extend(policies)
        session.commit()

    return '', 204


@blueprint.route('/user/<user_id>/policies/', methods=['PUT'])
@login_required({'admin'})
def replace_user_policies(user_id):
    """
    Overwrite the user's existing policies and replace them with the ones
    provided in the request.
    """
    policy_ids = _validate_policy_ids(flask.request.get_json().get('policies'))

    with flask.current_app.db.session as session:
        policies = lookup_policies(policy_ids)
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise NotFound('no user exists with ID: {}'.format(user_id))
        user.policies = policies
        session.commit()

    return '', 204


@blueprint.route('/user/<user_id>/policies/', methods=['DELETE'])
@login_required({'admin'})
def revoke_user_policies(user_id):
    """
    Revoke all the policies which this user has access to.
    """
    with flask.current_app.db.session as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise NotFound('no user exists with ID: {}'.format(user_id))
        # Set user's policies to empty list.
        user.policies = []
        session.commit()
    return '', 204


@blueprint.route('/user/<user_id>/policies/<policy_id>', methods=['DELETE'])
@login_required({'admin'})
def revoke_user_policy(user_id, policy_id):
    """
    Revoke a specific policy (the policy ID in the path) granted to a user
    (specified by user ID in the path).
    """
    with flask.current_app.db.session as session:
        user = session.query(User).filter_by(User.id == user_id).first()
        if not user:
            raise NotFound('no user exists with ID: {}'.format(user_id))
        user.policies.remove(policy_id)
        session.flush()
    return '', 204


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
            policy = session.query(Policy).filter_by(id=policy_id).first()
            if not policy:
                raise ValueError(
                    'policy not registered in fence: {}'
                    .format(policy_id)
                )
            policies.append(policy)
    return policies


def _list_all_policies(session):
    """
    List all the policies existing in a database session.

    Args:
        session (sqlalchemy.orm.session.Session)

    Return:
        List[fence.models.Policy]
    """
    return session.query(Policy).all()


def _get_user_policy_ids(user_id):
    """
    List the IDs for policies which are granted to this user, according to the
    fence database.

    Args:
        user_id (str): the id for a user

    Return:
        List[str]: list of policies granted to the user
    """
    with flask.current_app.db.session as session:
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            raise NotFound('no user exists with ID: {}'.format(user_id))
        return [policy.id for policy in user.policies]


def _validate_policy_ids(policy_ids):
    """
    Check some user-inputted policy IDs which should correspond to policies in
    arborist.

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
