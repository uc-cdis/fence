from unittest.mock import MagicMock, patch

import fence
from fence.scripting.google_monitor import _get_users_without_access, validation_check

from fence.models import (
    User,
    UserServiceAccount,
    ServiceAccountAccessPrivilege,
    Bucket,
    Project,
    ProjectToBucket,
)
from fence.resources.google.access_utils import force_add_service_accounts_to_access


def test_validation_check_valid(
    valid_google_project_patcher,
    valid_service_account_patcher,
    register_user_service_account,
    db_session,
    cloud_manager,
):
    """
    Test validation check when everything is valid. Make sure the
    valid registered service accounts maintain their access.
    """
    (
        fence.scripting.google_monitor._get_user_email_list_from_google_project_with_owner_role
    ) = MagicMock()

    (
        fence.scripting.google_monitor._send_emails_informing_service_account_removal
    ) = MagicMock()

    (fence.scripting.google_monitor._get_service_account_removal_reasons) = MagicMock()

    validation_check(db=None)
    assert (
        fence.scripting.google_monitor._send_emails_informing_service_account_removal.call_count
        == 0
    )
    _assert_access(register_user_service_account["service_account"].email, db_session)


def test_validation_check_one_invalid(
    valid_google_project_patcher,
    valid_service_account_patcher,
    register_user_service_account,
    invalid_service_account_patcher,
    db_session,
    cloud_manager,
):
    """
    Test validation check when everything is valid. Make sure the
    valid registered service accounts maintain their access.
    """
    (
        fence.scripting.google_monitor._get_user_email_list_from_google_project_with_owner_role
    ) = MagicMock()

    (
        fence.scripting.google_monitor._send_emails_informing_service_account_removal
    ) = MagicMock()

    (fence.scripting.google_monitor._get_service_account_removal_reasons) = MagicMock()

    validation_check(db=None)
    assert (
        fence.scripting.google_monitor._send_emails_informing_service_account_removal.call_count
        == 1
    )
    _assert_access(register_user_service_account["service_account"].email, db_session)
    _assert_access(
        invalid_service_account_patcher["service_account"].email,
        db_session,
        has_access=False,
    )


def test_validation_check_service_account_removed(
    invalid_service_account_not_exist,
    valid_google_project_patcher,
    db_session,
    cloud_manager,
):
    """
    Test that an invalid service account whose policy does not exist is
    removed from the database
    """

    (
        fence.scripting.google_monitor._get_user_email_list_from_google_project_with_owner_role
    ) = MagicMock()

    (
        fence.scripting.google_monitor._send_emails_informing_service_account_removal
    ) = MagicMock()

    (fence.scripting.google_monitor._get_service_account_removal_reasons) = MagicMock()

    validation_check(db=None)
    assert (
        fence.scripting.google_monitor._send_emails_informing_service_account_removal.call_count
        == 1
    )
    assert (
        db_session.query(UserServiceAccount)
        .filter_by(email=invalid_service_account_not_exist["service_account"].email)
        .count()
    ) == 0


def test_validation_check_multiple_diff_projects(
    valid_service_account_patcher,
    valid_google_project_patcher,
    setup_data,
    db_session,
    cloud_manager,
):
    """
    Test validation check when everything is valid. Make sure the
    valid registered service accounts maintain their access.
    """
    registered_service_accounts = ["1@example.com"]
    registered_service_accounts_2 = ["2@example.com", "3@example.com"]

    (
        fence.scripting.google_monitor._get_user_email_list_from_google_project_with_owner_role
    ) = MagicMock()

    (
        fence.scripting.google_monitor._send_emails_informing_service_account_removal
    ) = MagicMock()

    (fence.scripting.google_monitor._get_service_account_removal_reasons) = MagicMock()

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account.return_value
    ) = {"uniqueId": "1111111"}

    force_add_service_accounts_to_access(
        service_account_emails=registered_service_accounts,
        google_project_id="google_project_x",
        project_access=["project_1"],
    )

    force_add_service_accounts_to_access(
        service_account_emails=registered_service_accounts_2,
        google_project_id="google_project_y",
        project_access=["project_2"],
    )

    validation_check(db=None)
    assert (
        fence.scripting.google_monitor._send_emails_informing_service_account_removal.call_count
        == 0
    )
    _assert_access("1@example.com", db_session)
    _assert_access("2@example.com", db_session)
    _assert_access("3@example.com", db_session)


def test_get_users_without_access_no_access(test_user, test_project):
    """
    Test function _get_users_without_access when user does not have access to project
    """

    no_access = _get_users_without_access(
        db=None,
        auth_ids=[test_project.auth_id],
        user_emails=[test_user.email],
        check_linking=False,
    )
    assert len(no_access) == 1
    no_access_projects = no_access[test_user.email]
    assert len(no_access_projects) == 1
    assert no_access_projects[0] == test_project.auth_id


def test_get_users_without_access_with_access(test_linked_user_with_access):
    """
    Test function _get_users_without_access when user does have access to project
    """

    no_access = _get_users_without_access(
        db=None,
        auth_ids=["test_project"],
        user_emails=[test_linked_user_with_access.email],
        check_linking=False,
    )
    assert len(no_access) == 0


def test_get_users_without_access_with_access_by_linked(test_linked_user_with_access):
    """
    Test function _get_users_without_access when user does have access to project, by using linked email
    """

    no_access = _get_users_without_access(
        db=None,
        auth_ids=["test_project"],
        user_emails=["google_test_linked_user@gmail.com"],
        check_linking=False,
    )

    assert len(no_access) == 0


def _assert_access(service_account_email, db_session, has_access=True):
    service_account = (
        db_session.query(UserServiceAccount)
        .filter_by(email=service_account_email)
        .first()
    )
    assert service_account

    if has_access:
        assert (
            db_session.query(ServiceAccountAccessPrivilege)
            .filter_by(service_account_id=service_account.id)
            .all()
        )
    else:
        assert not (
            db_session.query(ServiceAccountAccessPrivilege)
            .filter_by(service_account_id=service_account.id)
            .all()
        )
