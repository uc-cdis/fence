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
import time
from io import StringIO
from urllib import quote

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch, mock_open


from fence.models import ServiceAccountToGoogleBucketAccessGroup


EXPECTED_ERROR_RESPONSE_KEYS = set(['status', 'error', 'error_description'])


def test_google_service_account_monitor_none(
        client, app, encoded_jwt_service_accounts_access,
        monkeypatch):
    """
    Test that the monitoring endpoint returns something when no creds
    exist.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access['jwt']
    test_file = None
    monkeypatch.setitem(
      app.config, 'CIRRUS_CFG', {'GOOGLE_APPLICATION_CREDENTIALS': test_file})

    response = client.get(
        '/google/service_accounts/monitor',
        headers={'Authorization': 'Bearer ' + encoded_creds_jwt})

    assert response.status_code == 404


def test_google_service_account_monitor(
        client, app, encoded_jwt_service_accounts_access,
        monkeypatch):
    """
    Test that the monitoring endpoint returns something when given valid
    creds.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access['jwt']
    creds_file = u'{"client_email": "test123@example.com"}'
    path_mock = MagicMock()
    path_mock.return_value.path.return_value.exists.return_value = True

    mock_path = patch('fence.blueprints.google.os', path_mock)
    # mock_path = patch('os.path.exists', True)
    mocked_open = patch('__builtin__.open', mock_open(read_data=creds_file))

    monkeypatch.setitem(
      app.config, 'CIRRUS_CFG', {'GOOGLE_APPLICATION_CREDENTIALS': '.'})

    mocked_open.start()
    mock_path.start()
    response = client.get(
        '/google/service_accounts/monitor',
        headers={'Authorization': 'Bearer ' + encoded_creds_jwt})
    mocked_open.stop()
    mock_path.stop()

    assert response.status_code == 200
    assert response.json and 'service_account_email' in response.json
    assert response.json['service_account_email'] == 'test123@example.com'


def test_patch_service_account_no_project_change(
        client, app, db_session, encoded_jwt_service_accounts_access,
        register_user_service_account, user_can_manage_service_account_mock,
        valid_user_service_account_mock,
        update_service_account_permissions_mock):
    """
    Test that patching with no change to project_access successfully extends
    access for all projects the service account currently has access to.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access['jwt']
    service_account = register_user_service_account['service_account']

    response = client.patch(
        '/google/service_accounts/{}'.format(quote(service_account.email)),
        headers={'Authorization': 'Bearer ' + encoded_creds_jwt},
        content_type='application/json'
    )

    # check if success
    assert str(response.status_code).startswith('2')

    service_account_accesses = (
        db_session.query(
            ServiceAccountToGoogleBucketAccessGroup)
        .filter_by(service_account_id=service_account.id)
    ).all()

    # ensure access is the same
    assert (
        len(service_account_accesses)
        == len(register_user_service_account['bucket_access_groups'])
    )

    # make sure we actually extended access past the current time
    for access in service_account_accesses:
        assert access.expires > int(time.time())


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
