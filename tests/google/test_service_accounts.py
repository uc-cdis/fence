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
from io import StringIO

from fence.models import (
    Bucket,
    Project,
    ProjectToBucket,
    GoogleBucketAccessGroup,
    UserServiceAccount,
    ServiceAccountAccessPrivilege,
    ServiceAccountToGoogleBucketAccessGroup,
)

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch, mock_open


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


# @pytest.mark.skip(reason="not implemented yet")
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


# @pytest.mark.skip(reason="not implemented yet")
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


def test_valid_service_account_registration(
        app, db_session, client,
        encoded_jwt_service_accounts_access,cloud_manager,
        valid_google_project_patcher, valid_service_account_patcher):

    project = Project(
        id=1,
        auth_id="some_auth_id"
    )

    bucket = Bucket(
        id=1
    )

    db_session.add(project)
    db_session.add(bucket)
    db_session.commit()

    project_to_bucket = ProjectToBucket(
        project_id=1,
        bucket_id=1
    )

    db_session.add(project_to_bucket)
    db_session.commit()

    gbag = GoogleBucketAccessGroup(
        id=1,
        bucket_id=1,
        email="gbag@gmail.com"
    )

    db_session.add(gbag)
    db_session.commit()

    encoded_creds_jwt = encoded_jwt_service_accounts_access['jwt']
    project_access = ["some_auth_id"]
    valid_service_account = {
        "service_account_email": "sa@gmail.com",
        "google_project_id": "project-id",
        "project_access": project_access
    }

    (
        cloud_manager.return_value
        .__enter__.return_value
        .get_service_account.return_value
    ) = {
        "uniqueId": "sa_unique_id",
        "email": "sa@gmail.com"
    }

    (
        cloud_manager.return_value
        .__enter__.return_value
        .add_member_to_group.return_value
    ) = {}

    assert len(db_session.query(UserServiceAccount).all()) == 0
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 0
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 0

    response = client.post(
        '/google/service_accounts',
        headers={'Authorization': 'Bearer ' + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type='application/json')

    assert response.status_code == 200

    assert len(db_session.query(UserServiceAccount).all()) == 1
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 1
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 1

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
    _assert_expected_error_info_structure(
        response.json['errors']['project_access']
    )


def _assert_expected_error_info_structure(data):
    assert EXPECTED_ERROR_RESPONSE_KEYS.issubset(data.keys())
