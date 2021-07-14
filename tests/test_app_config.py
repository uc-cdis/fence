"""
Test App Config from files
"""
import os
from mock import patch

import fence
from fence import app_init
from tests import test_settings
from tests.conftest import FakeBlobServiceClient


def test_app_config(config_path):
    """
    Flask application.
    """
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
        {"patch_name": "fence._setup_prometheus"},
        {
            "patch_name": "fence.resources.storage.StorageManager.__init__",
            "return_value": None,
        },
        {"patch_name": "fence._check_s3_buckets"},
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

    app_init(
        fence.app,
        test_settings,
        root_dir=root_dir,
        config_path=os.path.join(root_dir, config_path),
    )

    assert fence.app.config  # nosec

    for patcher in patchers:
        patcher.stop()
