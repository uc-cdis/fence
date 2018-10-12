"""
Define the ArboristClient class for interfacing with the arborist service for
RBAC.
"""

import json

from cdislogging import get_logger
import requests

from fence.errors import APIError


def _request_get_json(response):
    """
    Get the JSON from issuing a ``request``, or try to produce an error if the
    response was unintelligible.
    """
    try:
        return response.json()
    except ValueError as e:
        return {"error": str(e)}


class ArboristError(APIError):

    pass


class ArboristClient(object):
    """
    A singleton class for interfacing with the RBAC engine, "arborist".
    """

    def __init__(self, logger=None, arborist_base_url="http://arborist-service/"):
        self.logger = logger or get_logger("ArboristClient")
        self._base_url = arborist_base_url.strip("/")
        self._policy_url = self._base_url + "/policy/"
        self._resource_url = self._base_url + "/resource"
        self._role_url = self._base_url + "/role/"

    def healthy(self):
        """
        Indicate whether the arborist service is available and functioning.

        Return:
            bool: whether arborist service is available
        """
        try:
            response = requests.get(self._base_url + "/health")
        except requests.RequestException:
            return False
        return response.status_code == 200

    def get_resource(self, resource_path):
        """
        Return the information for a resource in arborist.

        Args:
            resource_path (str): path for the resource

        Return:
            dict: JSON representation of the resource
        """
        response = requests.get(self._resource_url + resource_path)
        if response.status_code == 404:
            return None
        return response.json()

    def list_policies(self):
        """
        List the existing policies.

        Return:
            dict: response JSON from arborist

        Example:

            {
                "policy_ids": [
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
        existing_policies = self.list_policies().get["policies"]
        return [
            policy_id for policy_id in policy_ids if policy_id not in existing_policies
        ]

    def create_resource(self, parent_path, resource_json, overwrite=False):
        """
        Create a new resource in arborist (does not affect fence database or
        otherwise have any interaction with userdatamodel).

        Used for syncing projects from dbgap into arborist resources.

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

        Raises:
            - ArboristError: if the operation failed (couldn't create resource)
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
        response = requests.post(path, json=resource_json)
        if response.status_code == 409:
            if overwrite:
                resource_path = path + resource_json["name"]
                return self.update_resource(resource_path, resource_json)
            else:
                return None
        data = _request_get_json(response)
        if "error" in data:
            msg = data["error"].get("message", str(data["error"]))
            self.logger.error(
                "could not create resource `{}` in arborist: {}".format(path, msg)
            )
            raise ArboristError(data["error"])
        self.logger.info("created resource {}".format(resource_json["name"]))
        return data

    def update_resource(self, path, resource_json):
        response = _request_get_json(requests.put(path, json=resource_json))
        if "error" in response:
            msg = response["error"].get("message", str(response["error"]))
            self.logger.error(
                "could not update resource `{}` in arborist: {}".format(path, msg)
            )
            raise ArboristError(response["error"])
        self.logger.info("updated resource {}".format(resource_json["name"]))
        return response

    def delete_resource(self, path):
        return _request_get_json(requests.delete(self._resource_url + path))

    def create_role(self, role_json):
        """
        Create a new role in arborist (does not affect fence database or
        otherwise have any interaction with userdatamodel).

        Used for syncing project permissions from dbgap into arborist roles.

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

        Raises:
            - ArboristError: if the operation failed (couldn't create role)
        """
        response = requests.post(self._role_url, json=role_json)
        data = _request_get_json(response)
        if response.status_code == 409:
            return None
        if "error" in data:
            self.logger.error(
                "could not create role `{}` in arborist: {}".format(
                    role_json["id"], data["error"]
                )
            )
            raise ArboristError(data["error"])
        self.logger.info("created role {}".format(role_json["id"]))
        return data

    def get_policy(self, policy_id):
        """
        Return the JSON representation of a policy with this ID.
        """
        response = requests.get(self._policy_url + policy_id)
        if response.status_code == 404:
            return None
        return response.json()

    def delete_policy(self, path):
        return _request_get_json(requests.delete(self._policy_url + path))

    def create_policy(self, policy_json, skip_if_exists=True):
        response = requests.post(self._policy_url, json=policy_json)
        data = _request_get_json(response)
        if response.status_code == 409:
            return None
        if "error" in data:
            self.logger.error(
                "could not create policy `{}` in arborist: {}".format(
                    policy_json["id"], data["error"]
                )
            )
            raise ArboristError(data["error"])
        self.logger.info("created policy {}".format(policy_json["id"]))
        return data
