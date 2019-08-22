"""
Define the ArboristClient class for interfacing with the arborist service for
RBAC.
"""

from functools import wraps
import json
import urllib.request, urllib.parse, urllib.error

import backoff
from cdislogging import get_logger
import requests

from fence.errors import Forbidden

from rbac.client.arborist.client import ArboristClient
from rbac.client.arborist.errors import ArboristError, ArboristUnhealthyError


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
    says it's unhealthy. By default, it will retry requests up to 5 times, waiting for a
    maximum of 10 seconds, before giving up and declaring arborist unavailable.
    """
    # set some defaults for when to give up: after 5 failures, or 10 seconds (these can
    # be overridden by keyword arguments)
    if "max_tries" not in backoff_kwargs:
        backoff_kwargs["max_tries"] = 5
    if "max_time" not in backoff_kwargs:
        backoff_kwargs["max_time"] = 10

    def decorator(method):
        def giveup():
            raise ArboristUnhealthyError()

        def wait_gen():
            # shorten the wait times between retries a little to fit our scale a little
            # better (aim to give up within 10 s)
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


class ArboristClient(ArboristClient):
    """
    A singleton class for interfacing with the RBAC engine, "arborist".
    """

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
