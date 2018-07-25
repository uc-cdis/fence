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
        self._policy_url = self._base_url + '/policy/'

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
