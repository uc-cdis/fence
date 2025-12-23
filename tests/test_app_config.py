"""
Test App Config from files
"""

import os
from unittest.mock import MagicMock
from flask import Flask
from mock import patch
import pytest

from azure.core.exceptions import ResourceNotFoundError
import fence
from fence import app_init, _check_azure_storage
from fence.config import FenceConfig
from tests.conftest import FakeBlobServiceClient


@pytest.mark.parametrize(
    "configuration_value,expected_value",
    [
        ("*", None),
        (None, None),
        ("", None),
        (" ", None),
        ("  ", None),
        ("", None),
        (" ", None),
        ("  ", None),
    ],
)
def test_check_azure_storage_configuration(configuration_value, expected_value):
    """
    test call to _check_azure_storage with azure_creds set to configuration_value for "AZ_BLOB_CREDENTIALS"
    This call should return expected_value
    """
    app = MagicMock()
    with patch("gen3config.Config.get", return_value=configuration_value):
        assert _check_azure_storage(app) is expected_value


def test_check_azure_storage_resource_not_found_error():
    """
    test call to _check_azure_storage with call to get_container_properties
    returns a azure.core.exceptions.ResourceNotFoundError
    """
    app = MagicMock()
    fake_blob_service_client = FakeBlobServiceClient()
    with patch("gen3config.Config.get", return_value="my fake connection string"):
        with patch(
            "fence.BlobServiceClient.from_connection_string",
            return_value=fake_blob_service_client,
        ):
            # mock call to container_client.get_container_properties raises a ResourceNotFoundError
            with patch(
                "tests.conftest.FakeContainerServiceClient.get_container_properties",
                side_effect=ResourceNotFoundError("Could not find container"),
            ):
                assert _check_azure_storage(app) is None


def test_app_config():
    """
    Test app_init call using the "test-fence-config.yaml"
    This includes the check to verify underlying storage
    """

    config_path = "test-fence-config.yaml"

    root_dir = os.path.dirname(os.path.realpath(__file__))

    # delete the record operation from the data blueprint, because right now it calls a
    # whole bunch of stuff on the arborist client to do some setup for the uploader role
    fence.blueprints.data.blueprint.deferred_functions = [
        f
        for f in fence.blueprints.data.blueprint.deferred_functions
        if f.__name__ != "record"
    ]

    fake_blob_service_client = FakeBlobServiceClient()

    patch_list = [
        {"patch_name": "fence.app_sessions"},
        {"patch_name": "fence.app_register_blueprints"},
        {"patch_name": "fence.oidc.oidc_server.OIDCServer.init_app"},
        {
            "patch_name": "fence.resources.storage.StorageManager.__init__",
            "return_value": None,
        },
        {"patch_name": "fence._check_buckets_aws_creds_and_region"},
        {
            "patch_name": "fence.BlobServiceClient.from_connection_string",
            "return_value": fake_blob_service_client,
        },
    ]

    patchers = []

    for patch_values in patch_list:
        patcher = (
            patch(patch_values["patch_name"], return_value=patch_values["return_value"])
            if "return_value" in patch_values.keys()
            else patch(patch_values["patch_name"])
        )
        patcher.start()
        patchers.append(patcher)

    # create a fresh local app
    local_app = Flask("test_app_config")
    app_init(
        local_app,
        root_dir=root_dir,
        config_path=os.path.join(root_dir, config_path),
    )

    assert fence.app.config  # nosec

    # Clean up registered blueprints to avoid error when repeatedly
    # registers blueprints with the same name in subsequent tests
    fence.app.blueprints = {}

    for patcher in patchers:
        patcher.stop()


def test_app_config_parent_child_study_mapping(monkeypatch):
    invalid_dbgap_configs = [
        {
            "parent_to_child_studies_mapping": {
                "phs001194": ["phs000571", "phs001843"],
                "phs001193": ["phs000572", "phs001844"],
            }
        },
        {
            "parent_to_child_studies_mapping": {
                "phs001194": ["phs0015623"],
                "phs001192": ["phs0001", "phs002"],
            }
        },
    ]
    with pytest.raises(Exception):
        FenceConfig._validate_parent_child_studies(invalid_dbgap_configs)
