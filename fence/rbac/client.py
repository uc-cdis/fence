"""
Define the ArboristClient class for interfacing with the arborist service for
RBAC.
"""

import json

import flask
import requests

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

    def __init__(self, arborist_base_url='http://arborist-service.default'):
        self._base_url = arborist_base_url.strip('/')
        self._role_url = self._base_url + '/role/'
        self._policy_url = self._base_url + '/policy/'

    def list_roles(self):
        """
        List the existing roles.

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
        Make a request for ``/role/<role_id>``.
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
        """
        return _request_get_json(requests.get(self._policy_url))

    def create_policy(self, policy_json):
        """
        Create a new policy in arborist and in the fence database.

        Return:
            dict: response JSON from arborist
        """
        with flask.current_app.db.session as session:
            response = _request_get_json(requests.post(
                self._policy_url, json=policy_json
            ))
            created_policies = response.get('created')
            if created_policies:
                for policy in created_policies:
                    session.add(Policy(
                        ID=policy['id'],
                        role_ids=policy['role_ids'],
                        resource_paths=policy['resource_paths'],
                    ))
            session.commit()
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
