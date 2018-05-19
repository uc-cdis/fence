from . import utils
import urlparse
import pytest

def test_fail_internal_access_key(client, auth_client):
    """
    Test ``GET /internal/access_key``.
    """
    path = '/internal/access_token'
    response = client.get(path, headers={"X-Forwarded-For":"127.0.0.1"})
    assert response.status_code == 404

def test_unauthorized_internal_access_key(client, auth_client):
    """
    Test ``GET /internal/access_key``.
    """
    path = '/internal/access_token'
    response = client.get(path)
    assert response.status_code == 401

