"""
Pytest fixtures for the RBAC tests, for doing things like adding policies to
the database to check the return from the RBAC endpoints.
"""

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock


import pytest

from fence.models import Policy
from fence.rbac.client import ArboristClient


@pytest.fixture
def mock_arborist_client(app, monkeypatch):
    """
    Mock the ``ArboristClient`` on the app, which would make requests to the
    arborist service for stuff like checking that some policies are valid.

    Return:
    """
    mock_client = MagicMock(ArboristClient)
    monkeypatch.setattr(app, 'arborist', mock_client)
    return mock_client


@pytest.fixture
def arborist_client():
    return ArboristClient()


@pytest.fixture
def example_policies():
    """
    Create some example policies and also add them to the database.

    Return:
        List[fence.models.Policy]: list of policies added
    """
    policies = [
        Policy(id='apple'),
        Policy(id='banana'),
        Policy(id='canteloupe'),
        Policy(id='durian'),
    ]
    return policies
