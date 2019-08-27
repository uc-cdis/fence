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
