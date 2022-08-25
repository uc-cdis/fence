"""
Test fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation
"""
from mock import patch
import pytest

from fence.blueprints.data.indexd import (
    AzureBlobStorageIndexedFileLocation,
    ANONYMOUS_USER_ID,
)


@pytest.mark.parametrize(
    "indexd_client",
    ["az"],
    indirect=True,
)
@pytest.mark.parametrize(
    "action,expires_in,force_signed_url,azure_creds,user_id,storage_account_matches,expect_signed",
    [
        ("download", 5, None, "fake conn str", "some user", False, False),
        ("download", 5, True, "fake conn str", "some user", True, True),
        ("download", 5, True, "fake conn str", "some user", False, False),
        ("download", 5, False, "fake conn str", "some user", True, False),
        ("download", 5, False, "fake conn str", "some user", False, False),
        ("download", 5, None, "fake conn str", "some user", True, True),
        ("download", 5, None, "*", "some user", True, True),
        ("download", 5, None, "*", "some user", False, False),
        ("download", 5, None, "*", ANONYMOUS_USER_ID, True, True),
        ("download", 5, None, "*", ANONYMOUS_USER_ID, False, False),
        ("download", 5, None, "fake conn str", ANONYMOUS_USER_ID, True, True),
        ("download", 5, None, "fake conn str", ANONYMOUS_USER_ID, False, False),
        ("upload", 5, None, "fake conn str", "some user", False, False),
        ("upload", 5, True, "fake conn str", "some user", True, True),
        ("upload", 5, True, "fake conn str", "some user", False, False),
        ("upload", 5, False, "fake conn str", "some user", True, False),
        ("upload", 5, False, "fake conn str", "some user", False, False),
        ("upload", 5, None, "fake conn str", "some user", True, True),
        ("upload", 5, None, "*", "some user", True, True),
        ("upload", 5, None, "*", "some user", False, False),
        ("upload", 5, None, "*", ANONYMOUS_USER_ID, True, True),
        ("upload", 5, None, "*", ANONYMOUS_USER_ID, False, False),
        ("upload", 5, None, "fake conn str", ANONYMOUS_USER_ID, True, True),
        ("upload", 5, None, "fake conn str", ANONYMOUS_USER_ID, False, False),
    ],
)
def test_get_signed_url(
    app,
    indexd_client,
    action,
    expires_in,
    force_signed_url,
    azure_creds,
    user_id,
    storage_account_matches,
    expect_signed,
):
    """
    test AzureBlobStorageIndexedFileLocation.get_signed_url
    """
    indexed_file_location_url = indexd_client["url"]

    with patch("cdispyutils.config.get_value", return_value=azure_creds):
        with patch(
            "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation._get_container_and_blob",
            return_value=("container_name", "blob_name"),
        ):
            with patch(
                "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation._check_storage_account_name_matches",
                return_value=storage_account_matches,
            ):
                with patch(
                    "fence.blueprints.data.indexd._get_auth_info_for_id_or_from_request",
                    return_value={"user_id": user_id},
                ):
                    azure_blob_storage_indexed_file_location = (
                        AzureBlobStorageIndexedFileLocation(indexed_file_location_url)
                    )
                    if force_signed_url == None:
                        return_url = (
                            azure_blob_storage_indexed_file_location.get_signed_url(
                                action=action,
                                expires_in=expires_in,
                            )
                        )
                    else:
                        return_url = (
                            azure_blob_storage_indexed_file_location.get_signed_url(
                                action=action,
                                expires_in=expires_in,
                                force_signed_url=force_signed_url,
                            )
                        )

                    if expect_signed:
                        assert "?" in return_url
                    else:
                        assert "?" not in return_url


@pytest.mark.parametrize(
    "indexed_file_location_url,blob_service_client_primary_hostame,expected_result",
    [
        (
            "az://fakeaccount.blob.core.windows.net/container5/blob6",
            "fakeaccount.blob.core.windows.net",
            True,
        ),
        (
            "az://fakeaccount.blob.core.windows.net/container5/blob6",
            "differentfakeaccount.blob.core.windows.net",
            False,
        ),
    ],
)
def test_check_storage_account_name_matches(
    indexed_file_location_url, blob_service_client_primary_hostame, expected_result
):
    """
    test AzureBlobStorageIndexedFileLocation._check_storage_account_name_matches
    """

    class MockBlobServiceClient:
        """
        Mock Blob Service Client
        """

        def __init__(self, primary_hostname):
            """
            Setup MockBlobServiceClient
            """
            self.primary_hostname = primary_hostname

    mock_blob_service_client = MockBlobServiceClient(
        primary_hostname=blob_service_client_primary_hostame
    )
    indexed_file = AzureBlobStorageIndexedFileLocation(indexed_file_location_url)

    assert (
        indexed_file._check_storage_account_name_matches(mock_blob_service_client)
        == expected_result
    )
