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
from datetime import datetime
from io import StringIO
from urllib.parse import quote

from fence.models import (
    Bucket,
    Project,
    ProjectToBucket,
    GoogleBucketAccessGroup,
    UserServiceAccount,
    ServiceAccountAccessPrivilege,
    ServiceAccountToGoogleBucketAccessGroup,
)

from fence.config import config

from unittest.mock import MagicMock, patch, mock_open


EXPECTED_ERROR_RESPONSE_KEYS = set(["status", "error", "error_description"])


def test_google_service_account_monitor_none(
    client, app, encoded_jwt_service_accounts_access, monkeypatch
):
    """
    Test that the monitoring endpoint returns something when no creds
    exist.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    test_file = None
    monkeypatch.setitem(
        config, "CIRRUS_CFG", {"GOOGLE_APPLICATION_CREDENTIALS": test_file}
    )

    response = client.get(
        "/google/service_accounts/monitor",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
    )

    assert response.status_code == 404


def test_google_service_account_monitor(
    client, app, encoded_jwt_service_accounts_access, monkeypatch
):
    """
    Test that the monitoring endpoint returns something when given valid
    creds.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    creds_file = '{"client_email": "test123@example.com"}'
    path_mock = MagicMock()
    path_mock.return_value.path.return_value.exists.return_value = True

    mock_path = patch("fence.blueprints.google.os", path_mock)
    # mock_path = patch('os.path.exists', True)
    mocked_open = patch("builtins.open", mock_open(read_data=creds_file))

    monkeypatch.setitem(config, "CIRRUS_CFG", {"GOOGLE_APPLICATION_CREDENTIALS": "."})

    mocked_open.start()
    mock_path.start()
    response = client.get(
        "/google/service_accounts/monitor",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
    )
    mocked_open.stop()
    mock_path.stop()

    assert response.status_code == 200
    assert response.json and "service_account_email" in response.json
    assert response.json["service_account_email"] == "test123@example.com"


def test_patch_service_account_no_project_change(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    register_user_service_account,
    user_can_manage_service_account_mock,
    valid_user_service_account_mock,
    revoke_user_service_account_from_google_mock,
    add_user_service_account_to_google_mock,
):
    """
    Test that patching with no arg project_access successfully extends
    access for all projects the service account currently has access to.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    service_account = register_user_service_account["service_account"]

    response = client.patch(
        "/google/service_accounts/{}".format(quote(service_account.email)),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
    )
    # check if success
    assert str(response.status_code).startswith("2")

    service_account_accesses = (
        db_session.query(ServiceAccountToGoogleBucketAccessGroup).filter_by(
            service_account_id=service_account.id
        )
    ).all()

    # ensure access is the same
    assert len(service_account_accesses) == len(
        register_user_service_account["bucket_access_groups"]
    )

    # make sure we actually extended access past the current time
    for access in service_account_accesses:
        assert access.expires > int(time.time())


def test_patch_service_account_expires_in(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    register_user_service_account,
    user_can_manage_service_account_mock,
    valid_user_service_account_mock,
    revoke_user_service_account_from_google_mock,
    add_user_service_account_to_google_mock,
):
    """
    Test that patching with a valid expires_in successfully extends
    access, and patching with an invalid expires_in does not.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    service_account = register_user_service_account["service_account"]

    # invalid expires_in: should fail
    requested_exp = "abc"  # expires_in must be int >0
    response = client.patch(
        "/google/service_accounts/{}?expires_in={}".format(
            quote(service_account.email), requested_exp
        ),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
    )
    assert response.status_code == 400  # check if failure

    # valid expires_in: should succeed
    requested_exp = 60
    response = client.patch(
        "/google/service_accounts/{}?expires_in={}".format(
            quote(service_account.email), requested_exp
        ),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
    )
    assert str(response.status_code).startswith("2")  # check if success

    # make sure the access was extended of the requested time
    # (allow up to 2 sec for runtime)
    service_account_accesses = (
        db_session.query(ServiceAccountToGoogleBucketAccessGroup).filter_by(
            service_account_id=service_account.id
        )
    ).all()
    for access in service_account_accesses:
        diff = access.expires - int(time.time())
        assert requested_exp - 2 <= diff <= requested_exp


def test_patch_service_account_dry_run_valid_empty_arg(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    register_user_service_account,
    user_can_manage_service_account_mock,
    valid_user_service_account_mock,
    revoke_user_service_account_from_google_mock,
    add_user_service_account_to_google_mock,
):
    """
    Test that patching with no arg project_access against _dry_run says the PATCH
    would successfully extend access.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    service_account = register_user_service_account["service_account"]

    response = client.patch(
        "/google/service_accounts/_dry_run/{}".format(quote(service_account.email)),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
    )
    # check if success
    assert str(response.status_code).startswith("2")
    assert "success" in response.json
    assert response.json.get("success")

    service_account_accesses = (
        db_session.query(ServiceAccountToGoogleBucketAccessGroup).filter_by(
            service_account_id=service_account.id
        )
    ).all()

    # ensure access is the same as before
    assert len(service_account_accesses) == len(
        register_user_service_account["bucket_access_groups"]
    )


def test_patch_service_account_dry_run_valid_new_access(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    register_user_service_account,
    user_can_manage_service_account_mock,
    valid_user_service_account_mock,
    revoke_user_service_account_from_google_mock,
    add_user_service_account_to_google_mock,
):
    """
    Test that patching with new project_access against _dry_run says the PATCH
    would successfully extend access if it's valid. BUT make sure it does NOT
    actually change the access.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    service_account = register_user_service_account["service_account"]

    response = client.patch(
        "/google/service_accounts/_dry_run/{}".format(quote(service_account.email)),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
        data={"project_access": ["another-valid-project"]},
    )
    # check if success
    assert str(response.status_code).startswith("2")
    assert "success" in response.json
    assert response.json.get("success")

    service_account_accesses = (
        db_session.query(ServiceAccountToGoogleBucketAccessGroup).filter_by(
            service_account_id=service_account.id
        )
    ).all()

    # ensure access is the same as before even though it was valid (since it's
    # the dry_run endpoint)
    assert len(service_account_accesses) == len(
        register_user_service_account["bucket_access_groups"]
    )


def test_patch_service_account_dry_run_invalid(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    register_user_service_account,
    user_can_manage_service_account_mock,
    invalid_user_service_account_mock,
    revoke_user_service_account_from_google_mock,
    add_user_service_account_to_google_mock,
):
    """
    Test that patching against dry_run when it would be invalid does not modify access.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    service_account = register_user_service_account["service_account"]

    response = client.patch(
        "/google/service_accounts/_dry_run/{}".format(quote(service_account.email)),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
        data=json.dumps({"project_access": ["this-project-doesnt-exist"]}),
    )
    # check if success
    assert str(response.status_code).startswith("4")
    assert "success" in response.json
    assert not response.json.get("success")

    service_account_accesses = (
        db_session.query(ServiceAccountToGoogleBucketAccessGroup).filter_by(
            service_account_id=service_account.id
        )
    ).all()

    # ensure access is the same
    assert len(service_account_accesses) == len(
        register_user_service_account["bucket_access_groups"]
    )


def test_patch_service_account_remove_all_access(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    register_user_service_account,
    user_can_manage_service_account_mock,
    valid_user_service_account_mock,
    revoke_user_service_account_from_google_mock,
    add_user_service_account_to_google_mock,
):
    """
    Test that patching with project_access as empty list successfully removes
    all projects the service account currently has access to.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    service_account = register_user_service_account["service_account"]

    response = client.patch(
        "/google/service_accounts/{}".format(quote(service_account.email)),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
        data=json.dumps({"project_access": []}),
    )
    # check if success
    assert str(response.status_code).startswith("2")

    service_account_accesses = (
        db_session.query(ServiceAccountToGoogleBucketAccessGroup).filter_by(
            service_account_id=service_account.id
        )
    ).all()

    # ensure access is the same
    assert len(service_account_accesses) == 0


def test_invalid_service_account_dry_run_errors(
    cloud_manager,
    client,
    app,
    encoded_jwt_service_accounts_access,
    valid_service_account_patcher,
    db_session,
):
    """
    Test that an invalid service account gives us the expected error structure
    """

    valid_service_account_patcher[
        "service_account_has_external_access"
    ].return_value = True

    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]

    db_session.add(Project(auth_id="project_a"))
    db_session.add(Project(auth_id="project_b"))
    db_session.commit()
    project_access = ["project_a", "project_b"]

    invalid_service_account = {
        "service_account_email": "test123@test.com",
        "google_project_id": "some-google-project-872340ajsdkj",
        "project_access": project_access,
    }

    response = client.post(
        "/google/service_accounts/_dry_run",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type="application/json",
    )

    assert response.status_code != 200
    _assert_expected_error_response_structure(response, project_access)


def test_invalid_service_account_has_external_access(
    client,
    app,
    encoded_jwt_service_accounts_access,
    valid_service_account_patcher,
    valid_google_project_patcher,
    db_session,
    cloud_manager,
):
    """
    Test that an invalid service account gives us the expected error structure
    """
    sa_patcher = valid_service_account_patcher
    proj_patcher = valid_google_project_patcher
    sa_patcher["service_account_has_external_access"].return_value = True
    proj_patcher["get_service_account_ids_from_google_members"].return_value = [
        "test123@test.com"
    ]
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "0", "email": "test123@test.com"}

    db_session.add(Project(auth_id="project_a"))
    db_session.add(Project(auth_id="project_b"))
    db_session.commit()
    project_access = ["project_a", "project_b"]

    invalid_service_account = {
        "service_account_email": "test123@test.com",
        "google_project_id": "some-google-project-872340ajsdkj",
        "project_access": project_access,
    }

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 400
    _assert_expected_error_response_structure(response, project_access)
    assert response.json["errors"]["service_account_email"]["status"] == 403


def test_invalid_service_account_has_invalid_type(
    client,
    app,
    encoded_jwt_service_accounts_access,
    valid_service_account_patcher,
    valid_google_project_patcher,
    db_session,
    cloud_manager,
):
    """
    Test that an invalid service account gives us the expected error structure
    """
    valid_service_account_patcher["is_valid_service_account_type"].return_value = False
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]

    db_session.add(Project(auth_id="project_a"))
    db_session.add(Project(auth_id="project_b"))
    db_session.commit()
    project_access = ["project_a", "project_b"]

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "0", "email": "test123@test.com"}

    invalid_service_account = {
        "service_account_email": "test123@test.com",
        "google_project_id": "some-google-project-872340ajsdkj",
        "project_access": project_access,
    }

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 400
    _assert_expected_error_response_structure(response, project_access)
    assert response.json["errors"]["service_account_email"]["status"] == 403


def test_invalid_service_account_not_owned_by_project(
    client,
    app,
    encoded_jwt_service_accounts_access,
    valid_service_account_patcher,
    valid_google_project_patcher,
    db_session,
    cloud_manager,
):
    """
    Test that an invalid service account gives us the expected error structure
    """
    (
        valid_service_account_patcher[
            "is_service_account_from_google_project"
        ].return_value
    ) = False
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]

    db_session.add(Project(auth_id="project_a"))
    db_session.add(Project(auth_id="project_b"))
    db_session.commit()
    project_access = ["project_a", "project_b"]

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "0", "email": "test123@test.com"}

    invalid_service_account = {
        "service_account_email": "test123@test.com",
        "google_project_id": "some-google-project-872340ajsdkj",
        "project_access": project_access,
    }

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 400
    _assert_expected_error_response_structure(response, project_access)
    assert response.json["errors"]["service_account_email"]["status"] == 403


def test_invalid_get_google_project_parent_org(
    client,
    app,
    encoded_jwt_service_accounts_access,
    valid_service_account_patcher,
    valid_google_project_patcher,
    db_session,
    cloud_manager,
):
    """
    Test that an invalid service account gives us the expected error structure
    """
    (
        valid_google_project_patcher["get_google_project_parent_org"].return_value
    ) = "some-parent-org"
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]

    db_session.add(Project(auth_id="project_a"))
    db_session.add(Project(auth_id="project_b"))
    db_session.commit()
    project_access = ["project_a", "project_b"]

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "0", "email": "test123@test.com"}

    invalid_service_account = {
        "service_account_email": "test123@test.com",
        "google_project_id": "some-google-project-872340ajsdkj",
        "project_access": project_access,
    }

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 400
    _assert_expected_error_response_structure(response, project_access)
    assert response.json["errors"]["google_project_id"]["status"] == 403


def test_valid_get_google_project_parent_org(
    cloud_manager,
    client,
    app,
    encoded_jwt_service_accounts_access,
    valid_service_account_patcher,
    valid_google_project_patcher,
    db_session,
    monkeypatch,
):
    """
    Test that a valid service account gives us the expected response when it has
    parent org BUT that org is whitelisted.
    """

    monkeypatch.setitem(
        config, "WHITE_LISTED_GOOGLE_PARENT_ORGS", ["whitelisted-parent-org"]
    )

    (
        valid_google_project_patcher["get_google_project_parent_org"].return_value
    ) = "whitelisted-parent-org"
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]

    db_session.add(Project(auth_id="project_a"))
    db_session.add(Project(auth_id="project_b"))
    db_session.commit()
    project_access = ["project_a", "project_b"]

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "0", "email": "test123@test.com"}

    valid_service_account = {
        "service_account_email": "test123@test.com",
        "google_project_id": "some-google-project-872340ajsdkj",
        "project_access": project_access,
    }

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 200


def test_invalid_google_project_has_invalid_membership(
    client,
    app,
    encoded_jwt_service_accounts_access,
    valid_service_account_patcher,
    valid_google_project_patcher,
    db_session,
    cloud_manager,
):
    """
    Test that an invalid service account gives us the expected error structure
    """
    valid_google_project_patcher[
        "get_google_project_valid_users_and_service_accounts"
    ].side_effect = Exception()
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]

    db_session.add(Project(auth_id="project_a"))
    db_session.add(Project(auth_id="project_b"))
    db_session.commit()
    project_access = ["project_a", "project_b"]

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "0", "email": "test123@test.com"}

    invalid_service_account = {
        "service_account_email": "test123@test.com",
        "google_project_id": "some-google-project-872340ajsdkj",
        "project_access": project_access,
    }

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 400
    _assert_expected_error_response_structure(response, project_access)
    assert response.json["errors"]["google_project_id"]["status"] == 403


def test_invalid_google_project_no_access(
    client,
    app,
    encoded_jwt_service_accounts_access,
    valid_service_account_patcher,
    valid_google_project_patcher,
    db_session,
):
    """
    Test that an invalid service account gives us the expected error structure
    """
    (
        valid_google_project_patcher["do_all_users_have_access_to_project"].return_value
    ) = False
    (
        valid_google_project_patcher[
            "get_project_access_from_service_accounts"
        ].return_value
    ) = []
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    project_access = ["project_a", "project_b"]
    invalid_service_account = {
        "service_account_email": "test123@test.com",
        "google_project_id": "some-google-project-872340ajsdkj",
        "project_access": project_access,
    }

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(invalid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 400
    _assert_expected_error_response_structure(response, project_access)
    assert response.json["errors"]["project_access"]["status"] != 200


def test_service_account_registration_expires_in(
    app,
    db_session,
    client,
    encoded_jwt_service_accounts_access,
    cloud_manager,
    valid_google_project_patcher,
    valid_service_account_patcher,
):
    """
    Test that a service account registration with a valid expires_in is
    successful, and that a registration with an invalid expires_in is not.
    """
    project = Project(id=1, auth_id="some_auth_id")

    bucket = Bucket(id=1)

    db_session.add(project)
    db_session.add(bucket)
    db_session.commit()

    project_to_bucket = ProjectToBucket(project_id=1, bucket_id=1)

    db_session.add(project_to_bucket)
    db_session.commit()

    gbag = GoogleBucketAccessGroup(id=1, bucket_id=1, email="gbag@gmail.com")

    db_session.add(gbag)
    db_session.commit()

    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    project_access = ["some_auth_id"]
    valid_service_account = {
        "service_account_email": "sa@gmail.com",
        "google_project_id": "project-id",
        "project_access": project_access,
    }

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "sa_unique_id", "email": "sa@gmail.com"}

    (
        cloud_manager.return_value.__enter__.return_value.add_member_to_group.return_value
    ) = {"email": "sa@gmail.com"}

    assert len(db_session.query(UserServiceAccount).all()) == 0
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 0
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 0

    # valid expires_in: should succeed
    requested_exp = 60

    response = client.post(
        "/google/service_accounts?expires_in={}".format(requested_exp),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )
    assert response.status_code == 200  # check if success

    assert len(db_session.query(UserServiceAccount).all()) == 1
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 1
    sa_to_bucket_entries = db_session.query(
        ServiceAccountToGoogleBucketAccessGroup
    ).all()
    assert len(sa_to_bucket_entries) == 1

    # make sure the access was granted for the requested time
    # (allow up to 2 sec for runtime)
    diff = sa_to_bucket_entries[0].expires - int(time.time())
    assert requested_exp - 2 <= diff <= requested_exp

    # invalid expires_in: should fail
    requested_exp = "abc"  # expires_in must be int >0

    response = client.post(
        "/google/service_accounts?expires_in={}".format(requested_exp),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )
    assert response.status_code == 400  # check if failure


def test_valid_service_account_registration(
    app,
    db_session,
    client,
    encoded_jwt_service_accounts_access,
    cloud_manager,
    valid_google_project_patcher,
    valid_service_account_patcher,
):
    """
    Test that a valid service account registration request returns
    200 and succesfully creates entries in database
    """
    project = Project(id=1, auth_id="some_auth_id")

    bucket = Bucket(id=1)

    db_session.add(project)
    db_session.add(bucket)
    db_session.commit()

    project_to_bucket = ProjectToBucket(project_id=1, bucket_id=1)

    db_session.add(project_to_bucket)
    db_session.commit()

    gbag = GoogleBucketAccessGroup(id=1, bucket_id=1, email="gbag@gmail.com")

    db_session.add(gbag)
    db_session.commit()

    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    project_access = ["some_auth_id"]
    valid_service_account = {
        "service_account_email": "sa@gmail.com",
        "google_project_id": "project-id",
        "project_access": project_access,
    }

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "sa_unique_id", "email": "sa@gmail.com"}

    (
        cloud_manager.return_value.__enter__.return_value.add_member_to_group.return_value
    ) = {"email": "sa@gmail.com"}

    assert len(db_session.query(UserServiceAccount).all()) == 0
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 0
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 0

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 200

    assert len(db_session.query(UserServiceAccount).all()) == 1
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 1
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 1


def test_valid_service_account_registration_multiple_service_accounts(
    app,
    db_session,
    client,
    encoded_jwt_service_accounts_access,
    cloud_manager,
    valid_google_project_patcher,
    valid_service_account_patcher,
):
    """
    Test that a valid service account registration request returns
    200 and succesfully creates entries in database when the Google project
    has both another valid service account in the project and a Google-managed
    system service account.
    """
    proj_patcher = valid_google_project_patcher
    project = Project(id=1, auth_id="some_auth_id")

    bucket = Bucket(id=1)

    db_session.add(project)
    db_session.add(bucket)
    db_session.commit()

    project_to_bucket = ProjectToBucket(project_id=1, bucket_id=1)

    db_session.add(project_to_bucket)
    db_session.commit()

    gbag = GoogleBucketAccessGroup(id=1, bucket_id=1, email="gbag@gmail.com")

    db_session.add(gbag)
    db_session.commit()

    google_project_id = "project-id"
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    project_access = ["some_auth_id"]
    proj_patcher["get_service_account_ids_from_google_members"].return_value = [
        "test-{}@test.com".format(google_project_id),
        "{}@compute-system.iam.gserviceaccount.com".format(google_project_id),
    ]
    valid_service_account = {
        "service_account_email": "sa@gmail.com",
        "google_project_id": google_project_id,
        "project_access": project_access,
    }

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "sa_unique_id", "email": "sa@gmail.com"}

    (
        cloud_manager.return_value.__enter__.return_value.add_member_to_group.return_value
    ) = {"email": "sa@gmail.com"}

    assert len(db_session.query(UserServiceAccount).all()) == 0
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 0
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 0

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 200

    assert len(db_session.query(UserServiceAccount).all()) == 1
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 1
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 1


def test_register_service_account_already_exists(
    app,
    db_session,
    client,
    encoded_jwt_service_accounts_access,
    cloud_manager,
    valid_google_project_patcher,
    valid_service_account_patcher,
):

    project = Project(id=1, auth_id="some_auth_id")

    bucket = Bucket(id=1)

    db_session.add(project)
    db_session.add(bucket)
    db_session.commit()

    project_to_bucket = ProjectToBucket(project_id=1, bucket_id=1)

    db_session.add(project_to_bucket)
    db_session.commit()

    gbag = GoogleBucketAccessGroup(id=1, bucket_id=1, email="gbag@gmail.com")

    db_session.add(gbag)
    db_session.commit()

    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    project_access = ["some_auth_id"]
    valid_service_account = {
        "service_account_email": "sa@gmail.com",
        "google_project_id": "project-id",
        "project_access": project_access,
    }

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "sa_unique_id", "email": "sa@gmail.com"}

    (
        cloud_manager.return_value.__enter__.return_value.add_member_to_group.return_value
    ) = {"email": "sa@gmail.com"}

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 200

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json["errors"]["service_account_email"]["status"] == 409

    assert len(db_session.query(UserServiceAccount).all()) == 1
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 1
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 1


def test_valid_project_limit_service_account_registration(
    app,
    db_session,
    client,
    encoded_jwt_service_accounts_access,
    cloud_manager,
    valid_google_project_patcher,
    valid_service_account_patcher,
):
    """
    Test that the projects are registered when there are SERVICE_ACCOUNT_LIMIT number of projects and the database is updated.
    """
    proj_patcher = valid_google_project_patcher
    project_access = []
    n_projects = config["SERVICE_ACCOUNT_LIMIT"]
    for i in range(n_projects):
        project = Project(id=i, auth_id="auth_id_{}".format(i))

        bucket = Bucket(id=i)

        db_session.add(project)
        db_session.add(bucket)
        db_session.commit()

        project_to_bucket = ProjectToBucket(project_id=i, bucket_id=i)

        db_session.add(project_to_bucket)
        db_session.commit()

        gbag = GoogleBucketAccessGroup(id=i, bucket_id=i, email="gbag@gmail.com")

        db_session.add(gbag)
        db_session.commit()

        project_access.append("auth_id_{}".format(i))

    google_project_id = "project-id"
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    proj_patcher["get_service_account_ids_from_google_members"].return_value = [
        "test-{}@test.com".format(google_project_id),
        "{}@compute-system.iam.gserviceaccount.com".format(google_project_id),
    ]
    valid_service_account = {
        "service_account_email": "sa@gmail.com",
        "google_project_id": google_project_id,
        "project_access": project_access,
    }

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "sa_unique_id", "email": "sa@gmail.com"}

    (
        cloud_manager.return_value.__enter__.return_value.add_member_to_group.return_value
    ) = {"email": "sa@gmail.com"}

    assert len(db_session.query(UserServiceAccount).all()) == 0
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 0
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 0

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 200

    assert len(db_session.query(UserServiceAccount).all()) == 1
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == n_projects
    assert (
        len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all())
        == n_projects
    )


def test_invalid_project_limit_service_account_registration(
    app,
    db_session,
    client,
    encoded_jwt_service_accounts_access,
    cloud_manager,
    valid_google_project_patcher,
):
    """
    Test that we get a 400 when there are SERVICE_ACCOUNT_LIMIT + 1 number of projects and the databse isn't updated.
    """
    proj_patcher = valid_google_project_patcher
    project_access = []
    n_projects = config["SERVICE_ACCOUNT_LIMIT"] + 1
    for i in range(n_projects):
        project = Project(id=i, auth_id="auth_id_{}".format(i))

        bucket = Bucket(id=i)

        db_session.add(project)
        db_session.add(bucket)
        db_session.commit()

        project_to_bucket = ProjectToBucket(project_id=i, bucket_id=i)

        db_session.add(project_to_bucket)
        db_session.commit()

        gbag = GoogleBucketAccessGroup(id=i, bucket_id=i, email="gbag@gmail.com")

        db_session.add(gbag)
        db_session.commit()

        project_access.append("auth_id_{}".format(i))

    google_project_id = "project-id"
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    proj_patcher["get_service_account_ids_from_google_members"].return_value = [
        "test-{}@test.com".format(google_project_id),
        "{}@compute-system.iam.gserviceaccount.com".format(google_project_id),
    ]
    valid_service_account = {
        "service_account_email": "sa@gmail.com",
        "google_project_id": google_project_id,
        "project_access": project_access,
    }

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "sa_unique_id", "email": "sa@gmail.com"}

    (
        cloud_manager.return_value.__enter__.return_value.add_member_to_group.return_value
    ) = {"email": "sa@gmail.com"}

    assert len(db_session.query(UserServiceAccount).all()) == 0
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 0
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 0

    response = client.post(
        "/google/service_accounts",
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        data=json.dumps(valid_service_account),
        content_type="application/json",
    )

    assert response.status_code == 400

    assert len(db_session.query(UserServiceAccount).all()) == 0
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 0
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 0


def test_patch_service_account_invalid_limit(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    register_user_service_account,
    user_can_manage_service_account_mock,
    valid_user_service_account_mock,
    revoke_user_service_account_from_google_mock,
    add_user_service_account_to_google_mock,
):
    """
    Test that patching with new project_access returns 400
    when more than SERVICE_ACCOUNT_LIMIT projects are trying to be registered.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    service_account = register_user_service_account["service_account"]
    n_projects = config["SERVICE_ACCOUNT_LIMIT"] + 1
    project_access = []
    for i in range(n_projects):
        project_access.append("valid-project-{}".format(i))
    valid_service_account = {
        "project_access": project_access,
    }

    assert len(db_session.query(UserServiceAccount).all()) == 1
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 2
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 2

    response = client.patch(
        "/google/service_accounts/{}".format(quote(service_account.email)),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
        data=json.dumps(valid_service_account),
    )

    assert response.status_code == 400

    assert len(db_session.query(UserServiceAccount).all()) == 1
    assert len(db_session.query(ServiceAccountAccessPrivilege).all()) == 2
    assert len(db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()) == 2


def test_patch_service_account_valid_limit(
    client,
    app,
    db_session,
    encoded_jwt_service_accounts_access,
    register_user_service_account,
    user_can_manage_service_account_mock,
    valid_user_service_account_mock,
    revoke_user_service_account_from_google_mock,
    add_user_service_account_to_google_mock,
):
    """
    Test that patching with new project_access returns 204
    when SERVICE_ACCOUNT_LIMIT number of projects is registered.
    """
    encoded_creds_jwt = encoded_jwt_service_accounts_access["jwt"]
    service_account = register_user_service_account["service_account"]
    project_access = []
    n_projects = config["SERVICE_ACCOUNT_LIMIT"]
    for i in range(n_projects):
        project = Project(id=i, auth_id="auth_id_{}".format(i))

        bucket = Bucket(id=i)

        db_session.add(project)
        db_session.add(bucket)
        db_session.commit()

        project_to_bucket = ProjectToBucket(project_id=i, bucket_id=i)

        db_session.add(project_to_bucket)
        db_session.commit()

        gbag = GoogleBucketAccessGroup(id=i, bucket_id=i, email="gbag@gmail.com")

        db_session.add(gbag)
        db_session.commit()

        project_access.append("auth_id_{}".format(i))

    response = client.patch(
        "/google/service_accounts/{}".format(quote(service_account.email)),
        headers={"Authorization": "Bearer " + encoded_creds_jwt},
        content_type="application/json",
        data=json.dumps({"project_access": project_access}),
    )
    assert response.status_code == 204

    service_account_accesses = (
        db_session.query(ServiceAccountToGoogleBucketAccessGroup).filter_by(
            service_account_id=service_account.id
        )
    ).all()

    assert len(service_account_accesses) == config["SERVICE_ACCOUNT_LIMIT"]


def _assert_expected_service_account_response_structure(data):
    assert "service_account_email" in data
    assert "google_project_id" in data
    assert "project_access" in data
    assert hasattr(data["project_access"], "__iter__")


def _assert_expected_error_response_structure(response, project_access):
    assert "success" in response.json
    assert "errors" in response.json
    assert "service_account_email" in response.json["errors"]
    _assert_expected_error_info_structure(
        response.json["errors"]["service_account_email"]
    )
    assert "google_project_id" in response.json["errors"]
    _assert_expected_error_info_structure(response.json["errors"]["google_project_id"])
    assert "project_access" in response.json["errors"]
    _assert_expected_error_info_structure(response.json["errors"]["project_access"])


def _assert_expected_error_info_structure(data):
    assert EXPECTED_ERROR_RESPONSE_KEYS.issubset(list(data.keys()))
