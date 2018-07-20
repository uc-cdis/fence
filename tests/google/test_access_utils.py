from fence.resources.google.access_utils import (
    is_valid_service_account_type,
    google_project_has_valid_membership,
)
from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    COMPUTE_ENGINE_API_SERVICE_ACCOUNT,
    GOOGLE_API_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
)
from cirrus.google_cloud.iam import (
    GooglePolicyMember
)


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
