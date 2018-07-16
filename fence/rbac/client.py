"""
Define the ArboristClient class for interfacing with the arborist service for
RBAC.
"""

import json

import requests


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
    A singleton class for interfacing with the RBAC engine, "arborist".
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
