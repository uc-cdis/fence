"""
Define the ArboristClient class for interfacing with the arborist service for
RBAC.
"""

from functools import wraps
import json
import urllib

import backoff
from cdislogging import get_logger
import requests

from fence.errors import Forbidden
from fence.rbac.errors import ArboristError, ArboristUnhealthyError


def _request_get_json(response):
    """
    Get the JSON from issuing a ``request``, or try to produce an error if the
    response was unintelligible.
    """
    try:
        return response.json()
    except ValueError as e:
        return {"error": str(e)}


def _arborist_retry(*backoff_args, **backoff_kwargs):
    """
    Decorate an ``ArboristClient`` method to retry requests to arborist, if arborist
    says it's unhealthy.
    """
    # set some defaults for when to give up: after 5 failures, or 10 seconds
    if "max_tries" not in backoff_kwargs:
        backoff_kwargs["max_tries"] = 5
    if "max_time" not in backoff_kwargs:
        backoff_kwargs["max_time"] = 10

    def decorator(method):
        def giveup():
            raise ArboristUnhealthyError()

        def wait_gen():
            # shorten the wait times a little to fit our scale a little better (aim to
            # give up within 10 s)
            for n in backoff.fibo():
                yield n / 2.0

        @wraps(method)
        def wrapper(self, *m_args, **m_kwargs):
            do_backoff = backoff.on_predicate(
                wait_gen, on_giveup=giveup, *backoff_args, **backoff_kwargs
            )
            do_backoff(self.healthy)
            return method(self, *m_args, **m_kwargs)

        return wrapper

    return decorator


class ArboristClient(object):
    """
    A singleton class for interfacing with the RBAC engine, "arborist".
    """

    def __init__(self, logger=None, arborist_base_url="http://arborist-service/"):
        self.logger = logger or get_logger("ArboristClient")
        self._base_url = arborist_base_url.strip("/")
        self._auth_url = self._base_url + "/auth/"
        self._health_url = self._base_url + "/health"
        self._policy_url = self._base_url + "/policy/"
        self._resource_url = self._base_url + "/resource"
        self._role_url = self._base_url + "/role/"
        self._user_url = self._base_url + "/user"
        self._client_url = self._base_url + "/client"
        self._group_url = self._base_url + "/group"

    def healthy(self):
        """
        Indicate whether the arborist service is available and functioning.

        Return:
            bool: whether arborist service is available
        """
        try:
            response = requests.get(self._health_url)
        except requests.RequestException as e:
            self.logger.error(
                "arborist not healthy; got requests exception: {}".format(str(e))
            )
            return False
        if response.status_code != 200:
            self.logger.error(
                "arborist not healthy; {} returned code {}".format(
                    self._health_url, response.status_code
                )
            )
        return response.status_code == 200

    @_arborist_retry()
    def auth_request(self, data):
        """
        Return:
            bool: authorization response
        """
        authed = False
        response = requests.post(self._auth_url.rstrip("/") + "/request", json=data)
        if response.status_code == 200:
            authed = bool(response.json()["auth"])
        elif response.status_code == 500:
            msg = "request to arborist failed: {}".format(response.json())
            raise ArboristError(message=msg, code=500)
        else:
            # arborist could send back a 400 for things like, the user has some policy
            # that it doesn't recognize, or the request is structured incorrectly; for
            # these cases we will default to unauthorized
            msg = "arborist denied auth request"
            try:
                detail = response.json()["error"]
                raise Forbidden("{}: {}".format(msg, detail))
            except (KeyError, ValueError):
                raise Forbidden(msg)

        return authed

    @_arborist_retry()
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

    @_arborist_retry()
    def list_resources_for_user(self, username):
        """
        Args:
            username (str)

        Return:
            List[str]: list of resource paths which the user has any access to
        """
        url = "{}/{}/resources".format(self._user_url, username)
        response = requests.get(url)
        data = _request_get_json(response)
        if response.status_code != 200:
            raise ArboristError(data.get("error", "unhelpful response from arborist"))
        return data["resources"]

    @_arborist_retry()
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

    @_arborist_retry()
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

    @_arborist_retry()
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
            if not overwrite:
                return None
            # overwrite existing resource
            resource_path = parent_path + resource_json["name"]
            self.logger.info("trying to overwrite resource {}".format(resource_path))
            self.delete_resource(resource_path)
            self.create_resource(parent_path, resource_json, overwrite=False)
            return
        data = _request_get_json(response)
        if isinstance(data, dict) and "error" in data:
            msg = data["error"]
            if isinstance(data["error"], dict):
                msg = data["error"].get("message", msg)
            resource = resource_json.get("path", "/" + resource_json.get("name"))
            self.logger.error(
                "could not create resource `{}` in arborist: {}".format(resource, msg)
            )
            raise ArboristError(data["error"])
        self.logger.info("created resource {}".format(resource_json["name"]))
        return data

    @_arborist_retry()
    def update_resource(self, path, resource_json):
        response = _request_get_json(requests.put(path, json=resource_json))
        if "error" in response:
            self.logger.error(
                "could not update resource `{}` in arborist: {}".format(
                    path, response["error"]
                )
            )
            raise ArboristError(response["error"])
        self.logger.info("updated resource {}".format(resource_json["name"]))
        return response

    @_arborist_retry()
    def delete_resource(self, path):
        return _request_get_json(requests.delete(self._resource_url + path))

    @_arborist_retry()
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
        if response.status_code == 409:
            # already exists; this is ok
            return None
        data = _request_get_json(response)
        if "error" in data:
            self.logger.error(
                "could not create role `{}` in arborist: {}".format(
                    role_json["id"], data["error"]
                )
            )
            raise ArboristError(data["error"])
        self.logger.info("created role {}".format(role_json["id"]))
        return data

    @_arborist_retry()
    def delete_role(self, role_id):
        response = requests.delete(self._role_url + role_id)
        if response.status_code == 404:
            # already doesn't exist, this is fine
            return
        elif response.status_code >= 400:
            raise ArboristError(
                "could not delete role in arborist: {}".format(response.json()["error"])
            )

    @_arborist_retry()
    def get_policy(self, policy_id):
        """
        Return the JSON representation of a policy with this ID.
        """
        response = requests.get(self._policy_url + policy_id)
        if response.status_code == 404:
            return None
        return response.json()

    @_arborist_retry()
    def delete_policy(self, path):
        return _request_get_json(requests.delete(self._policy_url + path))

    @_arborist_retry()
    def create_policy(self, policy_json, overwrite=False):
        if overwrite:
            response = requests.put(self._policy_url, json=policy_json)
        else:
            response = requests.post(self._policy_url, json=policy_json)
        data = _request_get_json(response)
        if response.status_code == 409:
            # already exists; this is ok, but leave warning
            self.logger.warn(
                "policy `{}` already exists in arborist".format(policy_json["id"])
            )
            return None
        if isinstance(data, dict) and "error" in data:
            self.logger.error(
                "could not create policy `{}` in arborist: {}".format(
                    policy_json["id"], data["error"]
                )
            )
            raise ArboristError(data["error"])
        self.logger.info("created policy {}".format(policy_json["id"]))
        return data

    @_arborist_retry()
    def create_user(self, user_info):
        """
        Args:
            user_info (dict):
                user information that goes in the request to arborist; see arborist docs
                for required field names. notably it's `name` not `username`
        """
        if "name" not in user_info:
            raise ValueError("create_user requires username `name` in user info")
        response = requests.post(self._user_url, json=user_info)
        data = _request_get_json(response)
        if response.status_code == 409:
            # already exists
            return
        elif response.status_code != 201:
            msg = data.get("error", "unhelpful response from arborist")
            self.logger.error(msg)

    @_arborist_retry()
    def grant_user_policy(self, username, policy_id):
        """
        MUST be user name, and not serial user ID
        """
        url = self._user_url + "/{}/policy".format(username)
        request = {"policy": policy_id}
        response = requests.post(url, json=request)
        data = _request_get_json(response)
        if response.status_code != 204:
            msg = data.get("error", "unhelpful response from arborist")
            if isinstance("error", dict):
                msg = data["error"].get("message", msg)
            self.logger.error(
                "could not grant policy `{}` to user `{}`: {}".format(
                    policy_id, username, msg
                )
            )
            return None
        self.logger.info("granted policy `{}` to user `{}`".format(policy_id, username))
        return data

    @_arborist_retry()
    def revoke_all_policies_for_user(self, username):
        url = self._user_url + "/{}/policy".format(urllib.quote(username))
        response = requests.delete(url)
        data = _request_get_json(response)
        if response.status_code != 204:
            msg = data.get("error", "unhelpful response from arborist")
            self.logger.error(
                "could not revoke policies from user `{}`: {}`".format(username, msg)
            )
            return None
        self.logger.info("revoked all policies from user `{}`".format(username))
        return data

    @_arborist_retry()
    def create_group(
        self, name, description="", users=None, policies=None, overwrite=False
    ):
        users = users or []
        policies = policies or []
        data = {"name": name, "users": users, "policies": policies}
        if description:
            data["description"] = description
        if overwrite:
            response = requests.put(self._group_url, json=data)
        else:
            response = requests.post(self._group_url, json=data)
        data = _request_get_json(response)
        if response.status_code == 409:
            # already exists; this is ok, but leave warning
            self.logger.warn("group `{}` already exists in arborist".format(name))
        if response.status_code != 201:
            msg = data.get("error", "unhelpful response from arborist")
            self.logger.error("could not create group {}: {}".format(name, msg))
            return None
        self.logger.info("created new group `{}`".format(name))
        if users:
            self.logger.info("group {} contains users: {}".format(name, list(users)))
            self.logger.info("group {} has policies: {}".format(name, list(policies)))
        return data

    @_arborist_retry()
    def grant_group_policy(self, group_name, policy_id):
        url = self._group_url + "/{}/policy".format(group_name)
        request = {"policy": policy_id}
        response = requests.post(url, json=request)
        data = _request_get_json(response)
        if response.status_code != 204:
            msg = data.get("error", "unhelpful response from arborist")
            if isinstance(data, dict) and "error" in data:
                msg = data["error"].get("message", msg)
            self.logger.error(
                "could not grant policy `{}` to group `{}`: {}".format(
                    policy_id, group_name, msg
                )
            )
            return None
        self.logger.info(
            "granted policy `{}` to group `{}`".format(policy_id, group_name)
        )
        return data

    @_arborist_retry()
    def create_user_if_not_exist(self, username):
        self.logger.info("making sure user exists: `{}`".format(username))
        user_json = {"name": username}
        response = requests.post(self._user_url, json=user_json)
        data = _request_get_json(response)
        if response.status_code == 409:
            return None
        if "error" in data:
            self.logger.error(
                "could not create user `{}` in arborist: {}".format(
                    username, data["error"]
                )
            )
            raise ArboristError(data["error"])
        self.logger.info("created user {}".format(username))
        return data

    @_arborist_retry()
    def create_client(self, client_id, policies):
        response = requests.post(
            self._client_url, json=dict(clientID=client_id, policies=policies or [])
        )
        data = _request_get_json(response)
        if "error" in data:
            self.logger.error(
                "could not create client `{}` in arborist: {}".format(
                    client_id, data["error"]
                )
            )
            raise ArboristError(data["error"])
        self.logger.info("created client {}".format(client_id))
        return data

    @_arborist_retry()
    def update_client(self, client_id, policies):
        # retrieve existing client, create one if not found
        response = requests.get("/".join((self._client_url, client_id)))
        if response.status_code == 404:
            self.create_client(client_id, policies)
            return

        # unpack the result
        data = _request_get_json(response)
        if "error" in data:
            self.logger.error(
                "could not fetch client `{}` in arborist: {}".format(
                    client_id, data["error"]
                )
            )
            raise ArboristError(data["error"])
        current_policies = set(data["policies"])
        policies = set(policies)

        # find newly granted policies, revoke all if needed
        url = "/".join((self._client_url, client_id, "policy"))
        if current_policies.difference(policies):
            # if some policies must be removed, revoke all and re-grant later
            response = requests.delete(url)
            if response.status_code != 204:
                data = _request_get_json(response)
                self.logger.error(
                    "could not revoke policies from client `{}` in arborist: {}".format(
                        client_id, data.get("error")
                    )
                )
                raise ArboristError(data.get("error"))
        else:
            # do not add policies that already exist
            policies.difference_update(current_policies)

        # grant missing policies
        for policy in policies:
            response = requests.post(url, json=dict(policy=policy))
            if response.status_code != 204:
                data = _request_get_json(response)
                self.logger.error(
                    "could not grant policy `{}` to client `{}` in arborist: {}".format(
                        policy, client_id, data["error"]
                    )
                )
                raise ArboristError(data["error"])
        self.logger.info("updated policies for client {}".format(client_id))

    @_arborist_retry()
    def delete_client(self, client_id):
        response = requests.delete("/".join((self._client_url, client_id)))
        self.logger.info("deleted client {}".format(client_id))
        return response.status_code == 204
