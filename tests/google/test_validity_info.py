"""
Tests for the fence.resources.google.access_utils.ValidityInfo object
"""
from fence.resources.google.validity import (
    ValidityInfo,
    GoogleProjectValidity,
    GoogleServiceAccountValidity,
)
from fence.models import Project
from fence.errors import NotFound

from unittest.mock import MagicMock, patch


def test_dict_like_validity_object():
    test_validity = ValidityInfo()

    # should evaluate to true by default
    assert test_validity

    # adding a new item should still result in "true" validity
    test_validity["test_validity123"] = True
    assert test_validity

    # adding a new FALSE item should result in FALSE validity
    test_validity["test_validity567"] = False
    assert not test_validity

    for key, _ in test_validity:
        assert key in ["test_validity123", "test_validity567"]


def test_valid_google_project(valid_google_project_patcher):
    """
    Test that when everything is valid, the GoogleProjectValidity is valid
    and has the expected information.
    """
    google_project_validity = GoogleProjectValidity("some-project-id")

    # should evaluate to true by default
    assert google_project_validity

    google_project_validity.check_validity(early_return=False)

    # should evaluate to true since all checks should result in valid project
    assert google_project_validity

    # test that it contains the default error information and it's true
    assert "valid_parent_org" in google_project_validity
    assert google_project_validity["valid_parent_org"]

    assert "valid_member_types" in google_project_validity
    assert google_project_validity["valid_member_types"]

    assert "members_exist_in_fence" in google_project_validity
    assert google_project_validity["members_exist_in_fence"]

    assert "new_service_account" in google_project_validity
    assert "service_accounts" in google_project_validity
    assert "access" in google_project_validity


def test_valid_google_project_service_accounts(
    app, valid_google_project_patcher, valid_service_account_patcher
):
    """
    Test that when everything is valid and there are service accounts (which
    are also all valid), the GoogleProjectValidity is valid
    and has the expected information.
    """
    patcher = valid_google_project_patcher

    patcher["get_service_account_ids_from_google_members"].return_value = [
        "some-account-id",
        "some-other-account-id",
    ]

    google_project_validity = GoogleProjectValidity("some-project-id")

    # should evaluate to true by default before checking validity
    assert google_project_validity

    google_project_validity.check_validity(early_return=False)

    # should evaluate to true since it's valid
    assert google_project_validity

    # test that it contains the correct error information
    assert "valid_parent_org" in google_project_validity
    assert google_project_validity["valid_parent_org"]

    assert "valid_member_types" in google_project_validity
    assert google_project_validity["valid_member_types"]

    assert "members_exist_in_fence" in google_project_validity
    assert google_project_validity["members_exist_in_fence"]

    assert "new_service_account" in google_project_validity
    assert "service_accounts" in google_project_validity
    assert hasattr(google_project_validity["service_accounts"], "__iter__")
    assert "some-account-id" in (google_project_validity["service_accounts"])
    assert "some-other-account-id" in (google_project_validity["service_accounts"])

    assert "access" in google_project_validity


def test_valid_google_project_access(
    valid_google_project_patcher, valid_service_account_patcher, db_session
):
    """
    Test that when everything is valid and there are access to data through
    projects (access is all valid), the GoogleProjectValidity is valid
    and has the expected information.
    """
    patcher = valid_google_project_patcher

    project1 = Project(auth_id="some-project-auth-id")
    project2 = Project(auth_id="some-other-project-auth-id")
    db_session.add(project1)
    db_session.add(project2)
    db_session.commit()

    patcher["get_project_access_from_service_accounts"].return_value = [
        project1,
        project2,
    ]

    google_project_validity = GoogleProjectValidity("some-project-id")

    # should evaluate to true by default before checking validity
    assert google_project_validity

    google_project_validity.check_validity(early_return=False)

    # should evaluate to true since it's valid
    assert google_project_validity

    # test that it contains the correct error information
    assert "valid_parent_org" in google_project_validity
    assert google_project_validity["valid_parent_org"]

    assert "valid_member_types" in google_project_validity
    assert google_project_validity["valid_member_types"]

    assert "members_exist_in_fence" in google_project_validity
    assert google_project_validity["members_exist_in_fence"]

    assert "new_service_account" in google_project_validity
    assert "service_accounts" in google_project_validity
    assert "access" in google_project_validity
    assert hasattr(google_project_validity["access"], "__iter__")
    assert "some-project-auth-id" in (google_project_validity["access"])
    assert "some-other-project-auth-id" in (google_project_validity["access"])


def test_valid_google_service_account(valid_service_account_patcher):
    """
    Test that when everything is valid, the GoogleServiceAccountValidity
    is valid and has the expected information.
    """
    google_service_account_validity = GoogleServiceAccountValidity(
        "some-account-id", "some-google-project-id"
    )

    # should evaluate to true by default
    assert google_service_account_validity

    google_service_account_validity.check_validity(early_return=False)

    # should evaluate to true since all checks should result in valid project
    assert google_service_account_validity

    # test that it contains the default error information and it's true
    assert "valid_type" in google_service_account_validity
    assert google_service_account_validity["valid_type"]

    assert "no_external_access" in google_service_account_validity
    assert google_service_account_validity["no_external_access"]

    assert "owned_by_project" in google_service_account_validity
    assert google_service_account_validity["owned_by_project"]


def test_invalid_google_project_parent_org(app, valid_google_project_patcher):
    """
    Test that when the Google Project is invalid, the resulting
    GoogleProjectValidity is False-y and contains the expected information.

    Here we're testing when the Google Project has a parent org (which is
    invalid).
    """
    patcher = valid_google_project_patcher
    patcher["get_google_project_parent_org"].return_value = "some-parent-org"

    google_project_validity = GoogleProjectValidity("some-project-id")

    # should evaluate to true by default before checking validity
    assert google_project_validity

    google_project_validity.check_validity(early_return=False)

    # should evaluate to false since invalid
    assert not google_project_validity

    # test that it contains the correct error information
    assert "valid_parent_org" in google_project_validity
    assert not google_project_validity["valid_parent_org"]

    assert "valid_member_types" in google_project_validity
    assert google_project_validity["valid_member_types"]

    assert "members_exist_in_fence" in google_project_validity
    assert google_project_validity["members_exist_in_fence"]

    assert "new_service_account" in google_project_validity
    assert "service_accounts" in google_project_validity
    assert "access" in google_project_validity


def test_invalid_google_project_membership(valid_google_project_patcher):
    """
    Test that when the Google Project is invalid, the resulting
    GoogleProjectValidity is False-y and contains the expected information.

    Here we're testing when the Google Project has invalid membership.
    """
    patcher = valid_google_project_patcher
    patcher[
        "get_google_project_valid_users_and_service_accounts"
    ].side_effect = Exception()

    google_project_validity = GoogleProjectValidity("some-project-id")

    # should evaluate to true by default before checking validity
    assert google_project_validity

    google_project_validity.check_validity(early_return=False)

    # should evaluate to false since invalid
    assert not google_project_validity

    # test that it contains the correct error information
    assert "valid_parent_org" in google_project_validity
    assert google_project_validity["valid_parent_org"]

    assert "valid_member_types" in google_project_validity
    assert not google_project_validity["valid_member_types"]

    assert "members_exist_in_fence" in google_project_validity
    assert not google_project_validity["members_exist_in_fence"]


def test_invalid_google_project_no_monitor(valid_google_project_patcher):
    """
    Test that when we can't determine the project number, we determine
    that the project is invalid. This happens when the monitoring service account
    does not have access on the project
    """
    patcher = valid_google_project_patcher
    patcher["get_google_project_number"].return_value = None

    google_project_validity = GoogleProjectValidity("some-project-id")

    # should evaluate to true by default before checking validity
    assert google_project_validity

    google_project_validity.check_validity(early_return=False)

    # should evaluate to false since invalid
    assert not google_project_validity

    # test that it contains the correct error information
    assert "valid_parent_org" in google_project_validity
    assert not google_project_validity["valid_parent_org"]

    assert "valid_member_types" in google_project_validity
    assert not google_project_validity["valid_member_types"]

    assert "members_exist_in_fence" in google_project_validity
    assert not google_project_validity["members_exist_in_fence"]

    assert "new_service_account" in google_project_validity
    assert "service_accounts" in google_project_validity
    assert "access" in google_project_validity


def test_invalid_google_project_access(valid_google_project_patcher, db_session):
    """
    Test that when the Google Project is invalid, the resulting
    GoogleProjectValidity is False-y and contains the expected information.

    Here we're testing when the Google Project's members have invalid access.
    """
    patcher = valid_google_project_patcher

    project = Project(auth_id="some-project-auth-id")
    db_session.add(project)
    db_session.commit()

    patcher["get_project_access_from_service_accounts"].return_value = [project]
    patcher["get_users_from_google_members"].return_value = ["test-user"]
    patcher["do_all_users_have_access_to_project"].return_value = False

    google_project_validity = GoogleProjectValidity("some-project-id")

    # should evaluate to true by default before checking validity
    assert google_project_validity

    google_project_validity.check_validity(early_return=False)

    # should evaluate to false since invalid
    assert not google_project_validity

    # test that it contains the correct error information
    assert "valid_parent_org" in google_project_validity
    assert google_project_validity["valid_parent_org"]

    assert "valid_member_types" in google_project_validity
    assert google_project_validity["valid_member_types"]

    assert "members_exist_in_fence" in google_project_validity
    assert google_project_validity["members_exist_in_fence"]

    assert "new_service_account" in google_project_validity
    assert "service_accounts" in google_project_validity
    assert "access" in google_project_validity
    assert hasattr(google_project_validity["access"], "__iter__")
    assert "some-project-auth-id" in (google_project_validity["access"])
    assert not google_project_validity["access"]["some-project-auth-id"]


def test_invalid_google_service_account_type(valid_service_account_patcher):
    """
    Test that when the Google Service Account is invalid, the resulting
    GoogleServiceAccountValidity is False-y and contains the expected
    information.

    Here we're testing when the Google Service Account's type is invalid.
    """
    patcher = valid_service_account_patcher
    patcher["is_valid_service_account_type"].return_value = False

    google_service_account_validity = GoogleServiceAccountValidity(
        "some-account-id", "some-google-project-id"
    )

    # should evaluate to true by default
    assert google_service_account_validity

    google_service_account_validity.check_validity(early_return=False)

    # should evaluate to true since all checks should result in valid project
    assert not google_service_account_validity

    # test that it contains the default error information and it's true
    assert "valid_type" in google_service_account_validity
    assert not google_service_account_validity["valid_type"]

    assert "no_external_access" in google_service_account_validity
    assert google_service_account_validity["no_external_access"]

    assert "owned_by_project" in google_service_account_validity
    assert google_service_account_validity["owned_by_project"]


def test_invalid_google_service_account_access(valid_service_account_patcher):
    """
    Test that when the Google Service Account is invalid, the resulting
    GoogleServiceAccountValidity is False-y and contains the expected
    information.

    Here we're testing when the Google Service Account has external access (
    which is not allowed).
    """
    patcher = valid_service_account_patcher
    patcher["service_account_has_external_access"].return_value = True

    google_service_account_validity = GoogleServiceAccountValidity(
        "some-account-id", "some-google-project-id"
    )

    # should evaluate to true by default
    assert google_service_account_validity

    google_service_account_validity.check_validity(early_return=False)

    # should evaluate to true since all checks should result in valid project
    assert not google_service_account_validity

    # test that it contains the default error information and it's true
    assert "valid_type" in google_service_account_validity
    assert google_service_account_validity["valid_type"]

    assert "no_external_access" in google_service_account_validity
    assert not google_service_account_validity["no_external_access"]

    assert "owned_by_project" in google_service_account_validity
    assert google_service_account_validity["owned_by_project"]


def test_invalid_google_service_account_ownership(valid_service_account_patcher):
    """
    Test that when the Google Service Account is invalid, the resulting
    GoogleServiceAccountValidity is False-y and contains the expected
    information.

    Here we're testing when the Google Service Account is not owned by the
    provided Google Project (which is not allowed).
    """
    patcher = valid_service_account_patcher
    patcher["is_service_account_from_google_project"].return_value = False

    google_service_account_validity = GoogleServiceAccountValidity(
        "some-account-id", "some-google-project-id"
    )

    # should evaluate to true by default
    assert google_service_account_validity

    google_service_account_validity.check_validity(early_return=False)

    # should evaluate to true since all checks should result in valid project
    assert not google_service_account_validity

    assert "owned_by_project" in google_service_account_validity
    assert not google_service_account_validity["owned_by_project"]


def test_invalid_service_account_does_not_exist(valid_service_account_patcher):
    """
    Test that when a Service Account that does not exist is requested
    for registration, the GoogleServiceAccountValidity is False-y and
    contains the expected infromation
    """

    patcher = valid_service_account_patcher
    patcher["get_service_account_policy"].side_effect = NotFound(
        "Test SA Policy Not Found"
    )

    google_service_account_validity = GoogleServiceAccountValidity(
        "some-account-id", "some-google-project-id"
    )

    # true by default
    assert google_service_account_validity

    google_service_account_validity.check_validity(early_return=False)

    # should be invalid due to being unable to get service account policy
    assert not google_service_account_validity
    assert "policy_accessible" in google_service_account_validity
    assert not google_service_account_validity["policy_accessible"]


def test_invalid_service_account_does_not_exist_external_access(
    valid_service_account_patcher,
):
    """
    Test that when a Service Account that does not exist is requested
    for registration, the GoogleServiceAccountValidity is False-y and
    no_external_access is NOT SET
    """

    patcher = valid_service_account_patcher
    patcher["get_service_account_policy"].side_effect = NotFound(
        "Test SA Policy Not Found"
    )

    google_service_account_validity = GoogleServiceAccountValidity(
        "some-account-id", "some-google-project-id"
    )

    # true by default
    assert google_service_account_validity

    google_service_account_validity.check_validity(early_return=False)

    # should be invalid due to being unable to get service account policy
    assert google_service_account_validity["no_external_access"] is None


def test_dict_like_validity_object_nested():
    """
    Test the dict-like functions of the base ValidityInfo object.
    """
    test_validity = ValidityInfo()
    nested_test_validity = ValidityInfo()

    # should evaluate to true by default
    assert test_validity

    # adding a new FALSE item should result in FALSE validity
    nested_test_validity["test_validity567"] = False
    assert not nested_test_validity

    # top level should be false now
    test_validity["nested"] = nested_test_validity
    assert not test_validity

    assert "nested" in test_validity
    assert "test_validity567" in test_validity["nested"]
    assert test_validity["nested"]["test_validity567"] is False
