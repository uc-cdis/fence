"""
Define the ArboristClient class for interfacing with the arborist service for
RBAC.
"""

import json

import flask
import requests

from fence.errors import UserError
from fence.models import Policy


def _request_get_json(response):
    """
    Get the JSON from issuing a ``request``, or try to produce an error if the
    response was unintelligible.
    """
    try:
        return response.json()
    except json.decoder.JSONDecodeError as e:
        return {'error': str(e)}


class ArboristClient(object):
    """
    A class for interfacing with the RBAC engine, "arborist".
    """

    def __init__(self, arborist_base_url='http://arborist-service/'):
        self._base_url = arborist_base_url.strip('/')
        self._role_url = self._base_url + '/role/'
        self._policy_url = self._base_url + '/policy/'
        self._resource_url = self._base_url + '/resource/'

    def list_roles(self):
        """
        List the existing roles.

        Expects JSON in this format from arborist:

            {
                "roles": [
                    "role-qwer",
                    "role-asdf",
                ]
            }

        Return:
            dict: response JSON from arborist
        """
        return _request_get_json(requests.get(self._role_url))

    def create_role(self, role_json):
        """
        Create a new role.

        Args:
            role_json (dict): dictionary of information about the role

        Return:
            dict: response JSON from arborist
        """
        return _request_get_json(requests.post(self._role_url, json=role_json))

    def _url_for_role(self, role_id):
        """Return the URL for the specific role given by ``role_id``."""
        return self._base_url + '/role/{}'.format(role_id)

    def role_request(self, role_id, method=None, **kwargs):
        """
        Make a request for ``/role/<role_id>``, which should be one of ``GET``,
        ``PATCH``, or ``DELETE``.

        Args:
            role_id (str): unique identifier for a role

        Keyword Args:
            method (str): HTTP method: 'GET', 'PUT', etc.

        Return:
            dict: response JSON from arborist
        """
        url = self._url_for_role(role_id)
        return _request_get_json(requests.request(method, url, **kwargs))

    def list_policies(self):
        """
        List the existing policies.

        Return:
            dict: response JSON from arborist

        Example:

            {
                "policies": [
                    "policy-abc",
                    "policy-xyz"
                ]
            }

        """
        return _request_get_json(requests.get(self._policy_url))

    def check_valid_policies(self, policy_dicts):
        """
        Do basic input validation on the policy to make sure it at least has
        the right fields.

        Args:
            policy_dict (dict): input JSON representing Policy

        Return:
            None

        Raises:
            - ``UserError``: if any validation fails
        """
        existing_role_ids = set(self.list_roles()['roles'])
        existing_resource_paths = set(self.list_resource_paths()['resources'])

        for policy_dict in policy_dicts:
            if 'id' not in policy_dict:
                raise UserError('policies missing required field "id"')
            if 'role_ids' not in policy_dict:
                raise UserError('policies missing required field "role_ids"')
            if 'resource_paths' not in policy_dict:
                raise UserError(
                    'policies missing required field "resource_paths"'
                )
            if self.policies_not_exist(policy_dict['id']):
                raise UserError(
                    'no policy exists with given ID: {}'
                    .format(policy_dict['id'])
                )
            for role_id in policy_dict['role_ids']:
                if role_id not in existing_role_ids:
                    raise UserError(
                        'cannot create policy; no role exists with ID: {}'
                        .format(role_id)
                    )
            for resource_path in policy_dict['resource_paths']:
                if resource_path not in existing_resource_paths:
                    raise UserError(
                        'cannot create policy; no resource exists with path:'
                        ' {}'
                        .format(resource_path)
                    )

    def list_resource_paths(self):
        """
        List all the paths of existing resources.

        Return:
            dict: response JSON from arborist

        Example:

            {
                "resources": [
                    "/",
                    "/a",
                    "/a/b",
                    "/x",
                    "/x/y",
                ]
            }
        """
        return _request_get_json(requests.get(self._resource_url))

    def policies_not_exist(self, policy_ids):
        """
        Return any policy IDs which do not exist in arborist. (So, if the
        result is empty, all provided IDs were valid.)

        Return:
            list: policies (if any) that don't exist in arborist
        """
        existing_policies = self.list_policies().get['policies']
        return [
            policy_id
            for policy_id in policy_ids
            if policy_id not in existing_policies
        ]

    def create_polices(self, policies_json):
        """
        Create a new policy in arborist and in the fence database.

        Example input:

            {
                "policies": [
                    "role_ids": ["role-a", "role-b"],
                    "resource_ids": ["/some/resource/1", "/some/resource/2"]
                ]
            }

        Args:
            policies_json (dict):

        Return:
            dict: response JSON from arborist
        """
        self.check_valid_policies(policies_json)

        with flask.current_app.db.session as session:
            response = _request_get_json(requests.post(
                self._policy_url, json=policies_json
            ))
            created_policies = response.get('created')
            if created_policies:
                for policy in created_policies:
                    session.add(Policy(
                        ID=policy['id'],
                        role_ids=policy['role_ids'],
                        resource_paths=policy['resource_paths'],
                    ))
            return response

    def delete_policy(self, policy_id):
        """
        Remove a policy from arborist engine and the fence database.
        """
        with flask.current_app.db.session as session:
            policy_url = self._policy_url + '/{}'.format(policy_id)
            response = _request_get_json(requests.delete(policy_url))
            if response.get('deleted'):
                policy_to_delete = (
                    session
                    .query(Policy)
                    .filter_by(ID=policy_id)
                    .first()
                )
                session.delete(policy_to_delete)
