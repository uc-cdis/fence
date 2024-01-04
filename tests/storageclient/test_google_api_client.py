"""
Module for mocking and testing of the
google API client
"""
import pytest

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

from fence.resources.storage.storageclient.errors import RequestError, NotFoundError


class TestGoogleCloudStorageClient(object):
    def test_client_creation(self, google_cloud_storage_client, test_cloud_manager):
        """
        Ensure that a google project id gets populated
        """
        assert google_cloud_storage_client.google_project_id == "test-google-project"

    def test_get_user_success(self, google_cloud_storage_client, test_cloud_manager):
        """
        Successful retrieval of a user
        """
        user_proxy = google_cloud_storage_client.get_user("user0")
        assert getattr(user_proxy, "username")

    def test_get_user_nonexistent_user(
        self, google_cloud_storage_client, test_cloud_manager
    ):
        """
        Retrieval of a nonexistent user
        """
        user = google_cloud_storage_client.get_user("NonExistent")
        assert user is None

    def test_add_bucket_acl_user_error(
        self, google_cloud_storage_client, test_cloud_manager
    ):
        """
        ACL addition to bucket with user not found
        """
        with pytest.raises(RequestError):
            google_cloud_storage_client.add_bucket_acl(
                access=["read-storage"], bucket="test_bucket", username="NonExistent"
            )

    def test_add_bucket_acl_bucket_error(
        self, google_cloud_storage_client, test_cloud_manager
    ):
        """
        ACL addition to bucket with bucket not found
        """
        with pytest.raises(RequestError):
            google_cloud_storage_client.add_bucket_acl(
                access=["read-storage"],
                bucket="NonExistent",
                username="user0_proxy_group@example.com",
            )

    def test_add_bucket_acl_success(
        self, google_cloud_storage_client, test_cloud_manager
    ):
        """
        Successful addition of ACL to bucket
        """
        response = google_cloud_storage_client.add_bucket_acl(
            access=["read-storage"],
            bucket="test_bucket",
            username="user0_proxy_group@example.com",
        )

        # the response should contain the newly added email
        assert response.get("email") == "user0_proxy_group@example.com"

    def test_add_bucket_acl_success_access(
        self, google_cloud_storage_client, test_cloud_manager
    ):
        """
        Successful addition of ACL to bucket even when an access level is
        supplied (should be ignored for Google)
        """
        response = google_cloud_storage_client.add_bucket_acl(
            access=["read-storage"],
            bucket="test_bucket",
            username="user0_proxy_group@example.com",
        )

        # the response should contain the newly added email
        assert response.get("email") == "user0_proxy_group@example.com"

    def test_delete_bucket_acl_success(
        self, google_cloud_storage_client, test_cloud_manager
    ):
        """
        Successful deletion of an acl
        """
        response = google_cloud_storage_client.delete_bucket_acl(
            bucket="test_bucket", user="user0_proxy_group@example.com"
        )
        assert not response

    def test_delete_bucket_acl_empty_name(
        self, google_cloud_storage_client, test_cloud_manager
    ):
        """
        Error handling when deleting an empty user from a bucket
        """
        with pytest.raises(RequestError):
            google_cloud_storage_client.delete_bucket_acl(bucket="test_bucket", user="")

    def test_delete_bucket_acl_empty_bucket(
        self, google_cloud_storage_client, test_cloud_manager
    ):
        """
        Error handling when deleting an empty bucket
        """
        with pytest.raises(RequestError):
            google_cloud_storage_client.delete_bucket_acl(
                bucket="", user="user0_proxy_group@example.com"
            )
