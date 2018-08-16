# pylint: disable=unused-argument
"""
Run tests for the policy endpoints in the RBAC blueprint.

Note that any test which will cause a call to
``fence.blueprints.rbac.lookup_policies`` must add the test policies to the
database, otherwise fence will raise an error from not finding a policy. Use
something like this:

    # Put the example policies in the database first.
    for policy in example_policies:
        db_session.add(policy)
"""

import json
try:
    import mock
except ImportError:
    from unittest import mock

from fence.blueprints.rbac import _get_user_policy_ids
from fence.rbac.client import ArboristClient
from fence.models import Policy, User


def test_list_policies(db_session, client, example_policies):
    """
    Test the ``/rbac/policy`` endpoint for listing existing policies.
    """
    # Put the example policies in the database first.
    for policy in example_policies:
        db_session.add(policy)

    policies_response = client.get('/rbac/policies/').json
    assert 'policies' in policies_response
    policy_ids = policies_response['policies']
    assert set(policy_ids) == set(policy.id for policy in example_policies)


def test_list_user_policies(db_session, client, user_client, example_policies):
    """
    Test listing the policies granted to the user using the
    ``/rbac/user/<user_id>/policies`` endpoint.
    """
    # Set up the user to have the example policies.
    user = db_session.query(User).filter_by(id=user_client.user_id).first()
    user.policies = example_policies

    path = '/rbac/user/{}/policies/'.format(user_client.user_id)
    policies_response = client.get(path)
    assert 'policies' in policies_response.json
    policies_from_db = _get_user_policy_ids(user_client.user_id)
    assert set(policies_from_db) == set(policies_response.json['policies'])


def test_grant_policy_to_user(
        client, db_session, user_client, example_policies,
        mock_arborist_client):
    """
    Test granting an additional policy to a user and check in the policy
    listing endpoint and the database that the change goes through correctly.
    """
    # Put the example policies in the database first.
    for policy in example_policies:
        db_session.add(policy)

    # Get the list of policies before adding a new one
    path = '/rbac/user/{}/policies/'.format(user_client.user_id)
    policies_before = client.get(path).json['policies']

    # Grant user one additional policy for example
    policies = {'policies': [example_policies[0].id]}
    response = client.post(
        path, data=json.dumps(policies), content_type='application/json'
    )
    assert response.status_code == 204

    # Check that the new one was added correctly (shows up in endpoint).
    policies_after = client.get(path).json['policies']
    assert len(policies_after) == len(policies_before) + 1
    assert example_policies[0].id in policies_after
    # Check new policy is in database.
    db_policies = _get_user_policy_ids(user_client.user_id)
    assert set(policies_after) == set(db_policies)


def test_replace_user_policies(
        client, db_session, user_client, example_policies,
        mock_arborist_client):
    """
    Test overwriting the policies granted to a user and check in the policy
    listing endpoint and the database that the change goes through correctly.
    """
    # Put the example policies in the database first.
    for policy in example_policies:
        db_session.add(policy)

    policies_even = example_policies[::2]
    policies_odd = example_policies[1::2]

    # Set up the user to have every odd example policy in the test list.
    user = db_session.query(User).filter_by(id=user_client.user_id).first()
    user.policies = policies_odd

    # Hit the endpoint and change the user's policies to be every even test
    # policy.
    path = '/rbac/user/{}/policies/'.format(user_client.user_id)
    policies = {'policies': [policy.id for policy in policies_even]}
    response = client.put(
        path, data=json.dumps(policies), content_type='application/json'
    )
    assert response.status_code == 204

    # Check policies from endpoint.
    expected_policy_ids = [policy.id for policy in policies_even]
    policies_after = client.get(path).json['policies']
    assert set(policies_after) == set(expected_policy_ids)
    # Check policies in database.
    user_policies_from_db = _get_user_policy_ids(user_client.user_id)
    assert set(user_policies_from_db) == set(expected_policy_ids)


def test_revoke_user_policies(client, user_client):
    """
    Test revoking all the policies granted to a user using the
    ``/rbac/user/policies/`` endpoint with a ``DELETE`` call.
    """
    path = '/rbac/user/{}/policies/'.format(user_client.user_id)
    response = client.delete(path)
    assert response.status_code == 204

    # Check policies response for the user is empty.
    policies_after = client.get(path).json['policies']
    assert policies_after == []
    # Check policies in database are empty.
    db_policies = _get_user_policy_ids(user_client.user_id)
    assert db_policies == []


def test_create_policy(client, db_session):
    """
    Test creating a policy using the ``/rbac/policies/`` endpoint, adding the
    policy in the fence database and also registering it in arborist.
    """
    policies = {'policies': ['test-policy-1', 'test-policy-2']}
    with (
        mock.patch.object(
            ArboristClient, 'policies_not_exist', return_value=[]
        )
    ) as mock_policies_not_exist:
        response = client.post(
            '/rbac/policies/',
            data=json.dumps(policies),
            content_type='application/json',
        )
        mock_policies_not_exist.assert_called_once()
    assert response.status_code == 201
    policy = (
        db_session
        .query(Policy)
        .filter(Policy.id == 'test-policy-1')
        .first()
    )
    assert policy
