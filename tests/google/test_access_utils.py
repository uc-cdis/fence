import pytest
from fence.resources.google.access_utils import update_google_groups_for_users, GoogleUpdateException


def test_update_google_groups_for_users_success(cloud_manager):
    """
    Test successful update of Google Groups for a single user.
    """
    google_single_user_mapping = {"user@test.com": ["group1@google.com", "group2@google.com"]}
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.return_value = ["group2@google.com"]

    update_google_groups_for_users(google_single_user_mapping)

    mock_gcm_instance.get_groups_for_user.assert_called_once_with("user@test.com")
    mock_gcm_instance.add_member_to_group.assert_called_once_with("user@test.com", "group1@google.com")
    mock_gcm_instance.remove_member_from_group.assert_not_called()


def test_update_google_groups_for_users_remove_groups(cloud_manager):
    """
    Test successful removal of user from groups.
    """
    google_single_user_mapping = {"user@test.com": ["group1@google.com"]}
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.return_value = ["group1@google.com", "group2@google.com"]

    update_google_groups_for_users(google_single_user_mapping)

    mock_gcm_instance.get_groups_for_user.assert_called_once_with("user@test.com")
    mock_gcm_instance.add_member_to_group.assert_not_called()
    mock_gcm_instance.remove_member_from_group.assert_called_once_with("user@test.com", "group2@google.com")


def test_update_google_groups_for_users_error_adding_group(cloud_manager):
    """
    Test error when adding a user to a group, and ensure sync continues.
    """
    google_single_user_mapping = {"user@test.com": ["group1@google.com", "group2@google.com"]}
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.return_value = ["group2@google.com"]
    mock_gcm_instance.add_member_to_group.side_effect = Exception("Error adding group")

    with pytest.raises(GoogleUpdateException):
        update_google_groups_for_users(google_single_user_mapping)

    mock_gcm_instance.add_member_to_group.assert_called_once_with("user@test.com", "group1@google.com")
    mock_gcm_instance.remove_member_from_group.assert_not_called()


def test_update_google_groups_for_users_error_removing_group(cloud_manager):
    """
    Test error when removing a user from a group, and ensure sync continues.
    """
    google_single_user_mapping = {"user@test.com": ["group1@google.com"]}
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.return_value = ["group1@google.com", "group2@google.com"]
    mock_gcm_instance.remove_member_from_group.side_effect = Exception("Error removing group")

    with pytest.raises(GoogleUpdateException):
        update_google_groups_for_users(google_single_user_mapping)

    mock_gcm_instance.get_groups_for_user.assert_called_once_with("user@test.com")
    mock_gcm_instance.remove_member_from_group.assert_called_once_with("user@test.com", "group2@google.com")


def test_update_google_groups_for_users_get_groups_failure(cloud_manager):
    """
    Test failure when fetching user's current groups.
    """
    google_single_user_mapping = {"user@test.com": ["group1@google.com"]}
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.side_effect = Exception("Error fetching groups")

    with pytest.raises(GoogleUpdateException):
        update_google_groups_for_users(google_single_user_mapping)

    mock_gcm_instance.get_groups_for_user.assert_called_once_with("user@test.com")


def test_update_google_groups_for_multiple_users_success(cloud_manager):
    """
    Test successful update of Google Groups for multiple users.
    """
    google_single_user_mapping = {
        "user1@test.com": ["group1@google.com", "group2@google.com"],
        "user2@test.com": ["group3@google.com", "group4@google.com"]
    }
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.side_effect = [
        ["group2@google.com"],  # user1 current groups
        ["group3@google.com"]   # user2 current groups
    ]

    update_google_groups_for_users(google_single_user_mapping)

    # Assertions for user1@test.com
    mock_gcm_instance.get_groups_for_user.assert_any_call("user1@test.com")
    mock_gcm_instance.add_member_to_group.assert_any_call("user1@test.com", "group1@google.com")
    mock_gcm_instance.remove_member_from_group.assert_not_called()

    # Assertions for user2@test.com
    mock_gcm_instance.get_groups_for_user.assert_any_call("user2@test.com")
    mock_gcm_instance.add_member_to_group.assert_called_with("user2@test.com", "group4@google.com")
    mock_gcm_instance.remove_member_from_group.assert_not_called()


def test_update_google_groups_for_multiple_users_with_removals(cloud_manager):
    """
    Test update of Google Groups for multiple users with group removals.
    """
    google_single_user_mapping = {
        "user1@test.com": ["group1@google.com"],
        "user2@test.com": ["group3@google.com"]
    }
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.side_effect = [
        ["group1@google.com", "group2@google.com"],  # user1 current groups
        ["group3@google.com", "group4@google.com"]   # user2 current groups
    ]

    update_google_groups_for_users(google_single_user_mapping)

    # Assertions for user1@test.com (removing group2)
    mock_gcm_instance.get_groups_for_user.assert_any_call("user1@test.com")
    mock_gcm_instance.add_member_to_group.assert_not_called()
    mock_gcm_instance.remove_member_from_group.assert_any_call("user1@test.com", "group2@google.com")

    # Assertions for user2@test.com (removing group4)
    mock_gcm_instance.get_groups_for_user.assert_any_call("user2@test.com")
    mock_gcm_instance.add_member_to_group.assert_not_called()
    mock_gcm_instance.remove_member_from_group.assert_any_call("user2@test.com", "group4@google.com")


def test_update_google_groups_for_multiple_users_partial_failure(cloud_manager):
    """
    Test partial failure when updating groups for multiple users, ensuring sync continues.
    """
    google_single_user_mapping = {
        "user1@test.com": ["group1@google.com", "group2@google.com"],
        "user2@test.com": ["group3@google.com", "group4@google.com"]
    }
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.side_effect = [
        ["group2@google.com"],  # user1 current groups
        ["group3@google.com"]   # user2 current groups
    ]
    mock_gcm_instance.add_member_to_group.side_effect = [
        None,  # Success for user1 group1
        Exception("Error adding group for user2")  # Failure for user2 group4
    ]

    with pytest.raises(GoogleUpdateException):
        update_google_groups_for_users(google_single_user_mapping)

    # Assertions for user1@test.com (successful)
    mock_gcm_instance.get_groups_for_user.assert_any_call("user1@test.com")
    mock_gcm_instance.add_member_to_group.assert_any_call("user1@test.com", "group1@google.com")
    mock_gcm_instance.remove_member_from_group.assert_not_called()

    # Assertions for user2@test.com (failed)
    mock_gcm_instance.get_groups_for_user.assert_any_call("user2@test.com")
    mock_gcm_instance.add_member_to_group.assert_any_call("user2@test.com", "group4@google.com")


def test_update_google_groups_for_multiple_users_with_removals_failure(cloud_manager):
    """
    Test failure when removing groups for multiple users, ensuring sync continues.
    """
    google_single_user_mapping = {
        "user1@test.com": ["group1@google.com"],
        "user2@test.com": ["group3@google.com"]
    }
    mock_gcm_instance = cloud_manager.return_value.__enter__.return_value
    mock_gcm_instance.get_groups_for_user.side_effect = [
        ["group1@google.com", "group2@google.com"],  # user1 current groups
        ["group3@google.com", "group4@google.com"]   # user2 current groups
    ]
    mock_gcm_instance.remove_member_from_group.side_effect = [
        None,  # Success for user1 removal
        Exception("Error removing group for user2")  # Failure for user2 removal
    ]

    with pytest.raises(GoogleUpdateException):
        update_google_groups_for_users(google_single_user_mapping)

    # Assertions for user1@test.com (removal success)
    mock_gcm_instance.get_groups_for_user.assert_any_call("user1@test.com")
    mock_gcm_instance.remove_member_from_group.assert_any_call("user1@test.com", "group2@google.com")

    # Assertions for user2@test.com (removal failure)
    mock_gcm_instance.get_groups_for_user.assert_any_call("user2@test.com")
    mock_gcm_instance.remove_member_from_group.assert_any_call("user2@test.com", "group4@google.com")