"""
WISEcode User services SDK
"""

import os
import logging
from typing import Dict

import requests


log = logging.getLogger(__name__)


_USER_SERVICE_BASE_URL = os.environ.get("USER_SERVICE_BASE_URL")
if not _USER_SERVICE_BASE_URL:
    raise KeyError("Missing required environment variable 'USER_SERVICE_BASE_URL'")

_USER_ACTION = "user"


def _headers(bearer_token: str) -> Dict:
    """
    Builds request headers
    """

    return {
        "Content-Type": "application/json",
        "Authorization": f"{bearer_token}",
    }


def _get(service: str, bearer_token: str) -> requests.Response:
    """
    Workflow service GET request
    """

    response = requests.get(
        f"{_USER_SERVICE_BASE_URL}{service}", headers=_headers(bearer_token)
    )
    log.debug(response.status_code)
    log.debug(response.content)

    return response


def read_user_jwt(bearer_token: str) -> requests.Response:
    """
    WISEcode User service read JWT User action call
    """

    return _get(f"{_USER_ACTION}/jwt", bearer_token)
