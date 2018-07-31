import pytest

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

from fence.resources.google.access_utils import (
    is_valid_service_account_type,
    service_account_has_external_access,
    google_project_has_valid_membership,
    do_get_service_account_from_google_project,
)
from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    COMPUTE_ENGINE_API_SERVICE_ACCOUNT,
    GOOGLE_API_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
)
from cirrus.google_cloud.errors import GoogleAPIError

from cirrus.google_cloud.iam import (
    GooglePolicyMember
)


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data

def test_is_valid_service_account_type_compute_engine_default(cloud_manager):
    """
    Test that COMPUTE_ENGINE_DEFAULT is a valid service account type
    for service account registration
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT
    assert is_valid_service_account_type(cloud_manager.project_id, 1)


def test_not_valid_service_account_type_google_api(cloud_manager):
    """
    Test that GOOGLE_API is not a valid service account type
    for service account registration
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = GOOGLE_API_SERVICE_ACCOUNT
    assert not is_valid_service_account_type(cloud_manager.project_id, 1)


def test_not_valid_service_account_type_compute_engine_api(cloud_manager):
    """
    Test that COMPUTE_ENGINE_API is not a valid service account type
    for service account registration
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = COMPUTE_ENGINE_API_SERVICE_ACCOUNT
    assert not is_valid_service_account_type(cloud_manager.project_id, 1)


def test_is_valid_service_account_type_user_managed(cloud_manager):
    """
    Test that USER_MANAGED is a valid service account type
    for service account registration
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = USER_MANAGED_SERVICE_ACCOUNT
    assert is_valid_service_account_type(cloud_manager.project_id, 1)


def test_service_account_has_role_in_service_policy(cloud_manager):
    """
    Test service account has roles in its policy
    """
    faked_json = {
        "bindings": [
            {
                "role": "roles/owner",
                "members": [
                    "user:mike@example.com",
                    "group:admins@example.com",
                    "domain:google.com",
                    "serviceAccount:my-other-app@appspot.gserviceaccount.com",
                ]
            },
            {
                "role": "roles/viewer",
                "members": ["user:sean@example.com"]
            }
        ]
    }

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    assert service_account_has_external_access('test_service_account')


def test_service_account_has_user_managed_key_in_service_policy(cloud_manager):
    """
    Test that service account has user managed keys in its policy
    """
    faked_json = {
        'etag': 'ACAB'
    }

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_keys_inf.return_value
    ) = ['key1', 'key2']

    assert service_account_has_external_access('test_service_account')


def test_service_account_does_not_have_external_access(cloud_manager):
    """
    Test that service account does not have any role or user managed key in its policy
    """
    faked_json = {
        'etag': 'ACAB'
    }

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_keys_info.return_value
    ) = []
    assert not service_account_has_external_access('test_service_account')


def test_service_account_has_external_access_raise_exception(cloud_manager):
    """
    In the case that a exception is raised when there is no access to the service account policy
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse({}, 403)

    with pytest.raises(GoogleAPIError):
        assert service_account_has_external_access('test_service_account')


def test_project_has_valid_membership(cloud_manager):
    """
    Test that a project with only users and service acounts
    has valid membership
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_project_membership.return_value
    ) = [
        GooglePolicyMember("user", "user@gmail.com"),
        GooglePolicyMember("serviceAccount", "sa@gmail.com")
        ]
    assert google_project_has_valid_membership(cloud_manager.project_id)


def test_project_has_invalid_membership(cloud_manager):
    """
    Test that a project with a non-users or service acounts
     has invalid membership
     """
    (
        cloud_manager.return_value.__enter__.return_value.get_project_membership.return_value
    ) = [
        GooglePolicyMember("user", "user@gmail.com"),
        GooglePolicyMember("otherType", "other@gmail.com")
    ]
    assert not google_project_has_valid_membership(cloud_manager.project_id)

def test_get_service_account_from_google_project_return_no_service_account(cloud_manager):
    """
    Test the scenario that there is no service account.
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_all_service_accounts.return_value
    ) = []
    service_accounts = do_get_service_account_from_google_project('test_project')

    assert (
            cloud_manager.return_value.__enter__.
            return_value.get_service_account.call_count
            ) == 0
    assert len(service_accounts) == 0


def test_get_service_account_from_google_project(cloud_manager):
    """
    Test get service account given project and service account id
    """
    faked_response = [
        {
            "name": "projects/test-project/serviceAccounts/test-service-account",
            "projectId": "test project id",
            "uniqueId": "116472687699820177",
            "email": "test@iam.com",
            "displayName": "test service",
            "etag": "BwVvhON",
            "oauth2ClientId": "11647280"
        },
        {
            "name": "projects/test-project/serviceAccounts/test-service-account2",
            "projectId": "test project idi 2",
            "uniqueId": "11647268769983477",
            "email": "test2@iam.com",
            "displayName": "test service",
            "etag": "BwVvhON",
            "oauth2ClientId": "1164725580"
        },
        ]

    (
        cloud_manager.return_value.__enter__.
        return_value.get_all_service_accounts.return_value
    ) = faked_response

    service_accounts = do_get_service_account_from_google_project('test_project')

    assert len(service_accounts) == 2

