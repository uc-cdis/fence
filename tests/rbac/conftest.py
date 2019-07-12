"""
Pytest fixtures for the RBAC tests, for doing things like adding policies to
the database to check the return from the RBAC endpoints.
"""

from unittest.mock import MagicMock


import pytest

from fence.rbac.client import ArboristClient


@pytest.fixture
def mock_arborist_client(app, monkeypatch):
    """
    Mock the ``ArboristClient`` on the app, which would make requests to the
    arborist service for stuff like checking that some policies are valid.

    Return:
    """
    mock_client = MagicMock(ArboristClient)
    monkeypatch.setattr(app, "arborist", mock_client)
    return mock_client


@pytest.fixture
def arborist_client():
    return ArboristClient()
