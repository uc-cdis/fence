import pytest

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

from cdisutilstest.code.request_mocker import RequestMocker
from cdisutilstest.data import (
    createAccount,
    cred,
    deleteAccount,
    editAccountAccessKey,
    editAccount,
    editVault,
    editVaultTemplate,
    listAccounts,
    listVaults,
    viewSystem,
)
from fence.resources.storage.storageclient.google import GoogleCloudStorageClient


@pytest.fixture
def google_cloud_storage_client():
    cred.credentials.update({"google_project_id": "test-google-project"})
    return GoogleCloudStorageClient(cred.credentials)


@pytest.fixture(scope="function")
def test_cloud_manager():
    manager = MagicMock()

    def mocked_get_group(username):
        response = {}
        if username == "user0":
            response = {"email": "user0_proxy_group@example.com"}
        return response

    def mocked_add_member_to_group(member_email, group_id):
        response = {}
        if (
            group_id == "test_bucket"
            and member_email == "user0_proxy_group@example.com"
        ):
            response = {"email": "user0_proxy_group@example.com"}
        else:
            raise Exception("cannot add {} to group {}".format(member_email, group_id))
        return response

    def mocked_remove_member_from_group(member_email, group_id):
        if (
            group_id == "test_bucket"
            and member_email == "user0_proxy_group@example.com"
        ):
            return {}
        else:
            raise Exception(
                "cannot remove {} from group {}".format(member_email, group_id)
            )

    manager.return_value.__enter__.return_value.get_group = mocked_get_group
    manager.return_value.__enter__.return_value.add_member_to_group = (
        mocked_add_member_to_group
    )
    manager.return_value.__enter__.return_value.remove_member_from_group = (
        mocked_remove_member_from_group
    )

    patch(
        "fence.resources.storage.storageclient.google.GoogleCloudManager", manager
    ).start()
    return manager


@pytest.fixture
def request_mocker():
    files = {
        "createAccount": createAccount.values,
        "deleteAccount": deleteAccount.values,
        "editAccountAccessKey": editAccountAccessKey.values,
        "editAccount": editAccount.values,
        "editVault": editVault.values,
        "editVaultTemplate": editVaultTemplate.values,
        "listAccounts": listAccounts.values,
        "listVaults": listVaults.values,
        "viewSystem": viewSystem.values,
    }
    req_mock = RequestMocker(files)
    patcher = patch("requests.request", req_mock.fake_request)
    patcher.start()

    yield req_mock

    patcher.stop()
