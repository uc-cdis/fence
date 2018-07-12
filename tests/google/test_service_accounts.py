"""
Tests for the /google/service_accounts endpoints.

NOTE: You can use the following helper assert functions when developing more
      tests:

      _assert_expected_service_account_response_structure(data)

          - Verifies that the structure of the response represents a service
            account
          - This is essentially a schema check against:
                {
                  "service_account_email": "string",
                  "google_project_id": "string",
                  "project_access": [
                    "string"
                  ]
                }

      _assert_expected_error_response_structure(data, project_access)

          - Verifies that the structure of the response represents an
            error response with info
          - provide which projects you expect error information for in
            project_access
          - This is essentially a schema check against:
                {
                  "success": bool,
                  "errors": {
                    "service_account_email": {
                      "status": int,
                      "error": "string",
                      "error_description": "string"
                    },
                    "google_project_id": {
                      "status": int,
                      "error": "string",
                      "error_description": "string"
                    },
                    "project_access": {
                      "ProjectA": {
                        "status": int,
                        "error": "string",
                        "error_description": "string"
                      },
                      "ProjectB": {
                        "status": int,
                        "error": "string",
                        "error_description": "string"
                      },
                      ...
                    }
                  }
                }
"""
import json
import pytest

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch


EXPECTED_ERROR_RESPONSE_KEYS = set(['status', 'error', 'error_description'])


@pytest.mark.skip(reason="not implemented yet")
def test_google_service_account_monitor(
        client, app, encoded_jwt_service_accounts_access):
    """
    Test that the monitoring endpoint returns something when given valid
    creds.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access['jwt']

    response = client.get(
        '/google/service_accounts/monitor',
        headers={'Authorization': 'Bearer ' + encoded_creds_jwt})

    assert response.status_code == 200
    assert response.json and 'service_account_email' in response.json


@pytest.mark.skip(reason="not implemented yet")
def test_invalid_service_account_dry_run_errors(
        client, app, encoded_jwt_service_accounts_access):
    """
    Test that an invalid service account gives us the expected error structure
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access['jwt']
    project_access = ["project_a", "project_b"]
    invalid_service_account = {
          "service_account_email": "test123@test.com",
          "google_project_id": "some-google-project-872340ajsdkj",
          "project_access": project_access
    }

    response = client.post(
        '/google/service_accounts/_dry_run',
        headers={'Authorization': 'Bearer ' + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type='application/json')

    _assert_expected_error_response_structure(response, project_access)

    assert response.status_code != 200


@pytest.mark.skip(reason="not implemented yet")
def test_invalid_service_account_registration_errors(
        client, app, encoded_jwt_service_accounts_access):
    """
    Test that an invalid service account gives us the expected error structure
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access['jwt']
    project_access = ["project_a", "project_b"]
    invalid_service_account = {
          "service_account_email": "test123@test.com",
          "google_project_id": "some-google-project-872340ajsdkj",
          "project_access": project_access
    }

    response = client.post(
        '/google/service_accounts',
        headers={'Authorization': 'Bearer ' + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type='application/json')

    _assert_expected_error_response_structure(response, project_access)

    assert response.status_code != 200


def _assert_expected_service_account_response_structure(data):
    assert 'service_account_email' in data
    assert 'google_project_id' in data
    assert 'project_access' in data
    assert hasattr(data['project_access'], '__iter__')


def _assert_expected_error_response_structure(response, project_access):
    assert 'success' in response.json
    assert 'errors' in response.json
    assert 'service_account_email' in response.json['errors']
    _assert_expected_error_info_structure(
        response.json['errors']['service_account_email'])
    assert 'google_project_id' in response.json['errors']
    _assert_expected_error_info_structure(
        response.json['errors']['google_project_id'])
    assert 'project_access' in response.json['errors']
    for project in project_access:
        assert project in response.json['errors']['project_access']
        _assert_expected_error_info_structure(
            response.json['errors']['project_access']['project_a'])


def _assert_expected_error_info_structure(data):
    assert EXPECTED_ERROR_RESPONSE_KEYS.issubset(data.keys())
