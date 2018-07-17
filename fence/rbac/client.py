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
        self._resource_url = self._base_url + '/resource'

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

    def create_resource(self, parent_path, resource_json):
        """
        Create a new resource in arborist (does not affect fence database or
        otherwise have any interaction with userdatamodel).

        Example schema for resource JSON:

            {
                "name": "some_resource",
                "description": "..."
                "subresources": [
                    {
                        "name": "subresource",
                        "description": "..."
                    }
                ]
            }

        Supposing we have some ``"parent_path"``, then the new resource will be
        created as ``/parent_path/some_resource`` in arborist.

        ("description" fields are optional, as are subresources, which default
        to empty.)

        Args:
            parent_path (str):
                the path (like a filepath) to the parent resource above this
                one; if this one is in the root level, then use "/"
            resource_json (dict):
                dictionary of resource information (see the example above)

        Return:
            dict: response JSON from arborist
        """
        # To add a subresource, all we actually have to do is POST the resource
        # JSON to its parent in arborist:
        #
        #     POST /resource/parent
        #
        # and now the new resource will exist here:
        #
        #     /resource/parent/new_resource
        #
        path = self._resource_url + parent_path
        return _request_get_json(requests.post(path, json=resource_json))

    def create_role(self, role_json):
        """
        Create a new role in arborist (does not affect fence database or
        otherwise have any interaction with userdatamodel).

        Example schema for the role JSON:

            {
                "id": "role",
                "description": "...",
                "permissions": [
                    {
                        "id": "permission",
                        "description": "...",
                        "action": {
                            "service": "...",
                            "method": "..."
                        },
                        "constraints": {
                            "key": "value",
                        }
                    }
                ]
            }

        ("description" fields are optional, as is the "constraints" field in
        the permission.)

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
