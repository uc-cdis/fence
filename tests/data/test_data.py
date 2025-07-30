import json
import time

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import urllib.parse
import uuid

import copy
import jwt
import pytest
import requests

import mock

import fence.blueprints.data.indexd


from fence.config import config
from fence.blueprints.data.indexd import ANONYMOUS_USER_ID, ANONYMOUS_USERNAME

from tests import utils


INDEXD_RECORD_WITH_PUBLIC_AUTHZ_POPULATED = {
    "did": "1",
    "baseid": "",
    "rev": "",
    "size": 10,
    "file_name": "file1",
    "urls": ["s3://bucket1/key"],
    "hashes": {},
    "metadata": {},
    "authz": ["/open"],
    "acl": [],
    "form": "",
    "created_date": "",
    "updated_date": "",
}

INDEXD_RECORD_WITH_PUBLIC_AUTHZ_AND_ACL_POPULATED = {
    "did": "1",
    "baseid": "",
    "rev": "",
    "size": 10,
    "file_name": "file1",
    "urls": ["s3://bucket1/key"],
    "hashes": {},
    "metadata": {},
    "authz": ["/open"],
    "acl": ["*"],
    "form": "",
    "created_date": "",
    "updated_date": "",
}


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_indexd_download_file(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1``.
    """
    indexed_file_location = indexd_client["indexed_file_location"]
    path = "/data/download/1"
    query_string = {"protocol": indexed_file_location}
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }

    with patch(
        "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation._check_storage_account_name_matches",
        return_value=True,
    ):
        response = client.get(path, headers=headers, query_string=query_string)
        assert response.status_code == 200
        assert "url" in list(response.json.keys())

        # defaults to signing url, check that it's not just raw url
        # unless using the default IndexedFileLocation.get_signed_url
        assert urllib.parse.urlparse(response.json["url"]).query != "" or (
            indexd_client["indexed_file_location"] == "https"
            and urllib.parse.urlparse(response.json["url"]).query == ""
        )


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "no_urls", "az", "https"],
    indirect=True,
)
def test_indexd_upload_file(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1``.
    """
    file_id = "1"
    indexed_file_location = indexd_client["indexed_file_location"]
    path = f"/data/upload/{file_id}?protocol=" + indexed_file_location
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_upload_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())
    assert file_id in response.json.get("url")


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_indexd_upload_file_key_error(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test upload with a missing configuration key should fail
    """
    file_id = "1"
    indexed_file_location = indexd_client["indexed_file_location"]
    path = f"/data/upload/{file_id}?protocol=" + indexed_file_location
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_upload_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }

    current_app = fence.blueprints.data.indexd.flask.current_app
    expected_value = copy.deepcopy(current_app.config)
    expected_value["DATA_UPLOAD_BUCKET"] = ""
    del expected_value["AZ_BLOB_CONTAINER_URL"]

    with patch.object(current_app, "config", expected_value):
        assert current_app.config == expected_value
        response = client.get(path, headers=headers)
        assert response.status_code == 500


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
@pytest.mark.parametrize("guid", ["1", "prefix/1"])
@pytest.mark.parametrize("file_name", ["some_test_file.txt", None])
def test_indexd_upload_file_filename(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
    guid,
    file_name,
):
    """
    Test ``GET /data/upload/<guid>?file_name=<file_name>``.
    """
    path = f"/data/upload/{guid}"
    if file_name:
        path += "?file_name=" + file_name
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_upload_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())

    name_in_url = file_name if file_name else guid.replace("/", "_")
    assert name_in_url in response.json.get("url")


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_indexd_upload_file_filename_key_error(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/upload/1?file_name=`` with an example file name
    using a missing configuration key which should fail.
    """
    file_name = "some_test_file.txt"
    path = "/data/upload/1?file_name=" + file_name
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_upload_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }

    current_app = fence.blueprints.data.indexd.flask.current_app
    expected_value = copy.deepcopy(current_app.config)
    expected_value["DATA_UPLOAD_BUCKET"] = ""
    del expected_value["AZ_BLOB_CONTAINER_URL"]

    with patch.object(current_app, "config", expected_value):
        assert current_app.config == expected_value
        response = client.get(path, headers=headers)
        assert response.status_code == 500


@pytest.mark.parametrize("indexd_client", ["s3"], indirect=True)
@pytest.mark.parametrize(
    "bucket,expected_status_code",
    [
        # fallback to default DATA_UPLOAD_BUCKET
        [None, 200],
        # bucket configured in S3_BUCKETS AND in ALLOWED_DATA_UPLOAD_BUCKETS
        ["bucket3", 200],
        # bucket configured in S3_BUCKETS but NOT in ALLOWED_DATA_UPLOAD_BUCKETS
        ["bucket2", 403],
        # bucket NOT configured in S3_BUCKETS or ALLOWED_DATA_UPLOAD_BUCKETS
        ["not-a-configured-bucket", 403],
    ],
)
def test_indexd_upload_file_bucket(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
    bucket,
    expected_status_code,
):
    """
    Test ``GET /data/upload/<guid>?bucket=<bucket>``.
    """
    guid = "1"
    path = f"/data/upload/{guid}"
    if bucket:
        path += f"?bucket={bucket}"
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_upload_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers)

    assert response.status_code == expected_status_code, response.json
    if expected_status_code == 200:
        assert "url" in response.json.keys()
        assert guid in response.json["url"]
        bucket_in_url = bucket if bucket else config["DATA_UPLOAD_BUCKET"]
        assert bucket_in_url in response.json["url"]


@pytest.mark.parametrize("indexd_client", ["nonexistent_guid"], indirect=True)
def test_indexd_upload_file_doesnt_exist(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/upload/1`` when 1 doesn't exist.
    """
    file_name = "some_test_file.txt"
    path = "/data/upload/1?file_name=" + file_name
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_upload_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers)

    assert response.status_code == 404


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_indexd_download_file_no_protocol(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1``.
    """

    path = "/data/download/1"
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_indexd_download_file_no_jwt(client, indexd_client, auth_client):
    """
    Test ``GET /data/download/1``.
    """
    path = "/data/download/1"
    response = client.get(path)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_indexd_unauthorized_download_file(
    client,
    oauth_client,
    unauthorized_user_client,
    indexd_client,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1``.
    """
    path = "/data/download/1"
    response = client.get(path)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_unauthorized_indexd_download_file(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1``.
    """
    path = "/data/download/1"

    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000789"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()

    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.unauthorized_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json

    mock_index_document.stop()


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_unauthorized_indexd_upload_file(
    client,
    oauth_client,
    encoded_jwt,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/upload/1``.
    """
    path = "/data/upload/1"

    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000789"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()

    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.unauthorized_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json

    mock_index_document.stop()


@pytest.mark.parametrize(
    "unauthorized_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_unavailable_indexd_upload_file(
    client,
    oauth_client,
    encoded_jwt,
    user_client,
    unauthorized_indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/upload/1``.
    """
    path = "/data/upload/1"

    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000789"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()

    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.unauthorized_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json

    mock_index_document.stop()


@pytest.mark.parametrize(
    "public_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_public_object_download_file(
    client,
    auth_client,
    public_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1``.
    """
    path = "/data/download/1"
    response = client.get(path)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())

    # defaults to signing url, check that it's not just raw url
    assert urllib.parse.urlparse(response.json["url"]).query != ""


@pytest.mark.parametrize(
    "public_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_public_object_download_file_no_force_sign(
    client,
    auth_client,
    public_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1?no_force_sign=True``.
    """

    no_force_sign_enabled_path = "/data/download/1?no_force_sign=True"
    response = client.get(no_force_sign_enabled_path)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())

    # make sure we honor no_force_sign, check that response is unsigned raw url
    assert urllib.parse.urlparse(response.json["url"]).query == ""

    no_force_sign_disabled_path = "/data/download/1?no_force_sign=False"
    response = client.get(no_force_sign_disabled_path)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())

    # url should be signed, as normal
    assert urllib.parse.urlparse(response.json["url"]).query != ""


@pytest.mark.parametrize(
    "public_bucket_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_public_bucket_download_file(
    client,
    auth_client,
    public_bucket_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1`` with public bucket
    """
    path = "/data/download/1"
    response = client.get(path)
    assert response.status_code == 200
    assert response.json.get("url")

    with patch(
        "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation._check_storage_account_name_matches",
        return_value=True,
    ):
        # we should NOT sign AWS S3 urls if the bucket itself is public
        if not public_bucket_indexd_client.startswith(
            "s3"
        ) and public_bucket_indexd_client not in ("https", "az"):
            # defaults to signing url, check that it's not just raw url
            assert urllib.parse.urlparse(response.json["url"]).query != ""


@pytest.mark.parametrize(
    "public_bucket_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az", "https"],
    indirect=True,
)
def test_public_bucket_download_file_no_force_sign(
    client,
    auth_client,
    public_bucket_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/upload/1`` with public bucket with no_force_sign request
    """
    path = "/data/download/1?no_force_sign=True"
    response = client.get(path)
    assert response.status_code == 200
    assert response.json.get("url")

    # make sure we honor no_force_sign, check that response is unsigned raw url
    assert urllib.parse.urlparse(response.json["url"]).query == ""


@pytest.mark.parametrize("public_bucket_indexd_client", ["s2"], indirect=True)
def test_public_bucket_unsupported_protocol_file(
    client,
    auth_client,
    public_bucket_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/upload/1`` with public bucket
    """
    path = "/data/download/1"
    response = client.get(path)
    assert response.status_code == 400

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json


def test_public_acl_object_upload_file(
    client,
    public_indexd_client,
):
    """
    Test `GET /data/upload/1` in which the `1` Indexd record has acl populated
    with the public value.
    """
    path = "/data/upload/1"
    response = client.get(path)

    assert response.status_code == 401
    assert response.data
    assert response.mimetype == "text/html"
    assert not response.json


def test_public_authz_object_upload_file(
    client,
    indexd_client_accepting_record,
    mock_arborist_requests,
    user_client,
    rsa_private_key,
    kid,
):
    """
    Test `GET /data/upload/1` in which the `1` Indexd record has authz
    populated with the public value.
    """
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000789"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.BlankIndex.index_document", index_document
    )
    mock_index_document.start()

    indexd_client_accepting_record(INDEXD_RECORD_WITH_PUBLIC_AUTHZ_POPULATED)
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    path = "/data/upload/1"
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in response.json

    mock_index_document.stop()


def test_public_authz_and_acl_object_upload_file_with_failed_authz_check(
    client,
    indexd_client_accepting_record,
    mock_arborist_requests,
    user_client,
    rsa_private_key,
    kid,
):
    """
    Test `GET /data/upload/1` in which the `1` Indexd record has authz
    populated with the public value, but the user doesn't have the correct
    authz permission'
    """
    indexd_client_accepting_record(INDEXD_RECORD_WITH_PUBLIC_AUTHZ_AND_ACL_POPULATED)
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": False}, 200)}})
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    path = "/data/upload/1"
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert response.data
    assert response.mimetype == "text/html"
    assert not response.json


def test_public_authz_and_acl_object_upload_file(
    client,
    indexd_client_accepting_record,
    mock_arborist_requests,
    user_client,
    rsa_private_key,
    kid,
):
    """
    Test `GET /data/upload/1` in which the `1` Indexd record has both authz and
    acl populated with public values. In this case, authz takes precedence over
    acl.
    """
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000789"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.BlankIndex.index_document", index_document
    )
    mock_index_document.start()

    indexd_client_accepting_record(INDEXD_RECORD_WITH_PUBLIC_AUTHZ_AND_ACL_POPULATED)
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    path = "/data/upload/1"
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in response.json

    mock_index_document.stop()


def test_non_public_authz_and_public_acl_object_upload_file(
    client,
    indexd_client_accepting_record,
    mock_arborist_requests,
    user_client,
    rsa_private_key,
    kid,
):
    """
    Test that a user can successfully generate an upload url for an Indexd
    record with a non-public authz field and a public acl field.
    """
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000789"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.BlankIndex.index_document", index_document
    )
    mock_index_document.start()

    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "did": "1",
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key"],
        "hashes": {},
        "metadata": {},
        "authz": ["/programs/DEV/projects/test"],
        "acl": ["*"],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    path = "/data/upload/1"
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in response.json

    mock_index_document.stop()


def test_anonymous_download_with_public_authz(
    client,
    indexd_client_accepting_record,
    mock_arborist_requests,
):
    """
    Test that it is possible for a user who is not logged in to generate a
    download url for a public authz record.
    """
    indexd_client_accepting_record(INDEXD_RECORD_WITH_PUBLIC_AUTHZ_POPULATED)
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})

    path = "/data/download/1"
    response = client.get(path)
    assert response.status_code == 200
    assert "url" in response.json


def test_download_fails_with_wrong_authz_and_public_acl(
    client,
    indexd_client_accepting_record,
    mock_arborist_requests,
    user_client,
    rsa_private_key,
    kid,
):
    """
    Test that generating a download url returns a 401 when acl is public, but
    authz is a permission the user doesn't have access to. Authz takes
    precedence.
    """
    indexd_record_with_wrong_authz_and_public_acl = {
        "did": "1",
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key"],
        "hashes": {},
        "metadata": {},
        "authz": ["/foo"],
        "acl": ["*"],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(indexd_record_with_wrong_authz_and_public_acl)
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": False}, 200)}})
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    path = "/data/download/1"
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert response.data
    assert response.mimetype == "text/html"
    assert not response.json


def test_indexd_download_with_uploader_unauthenticated(
    client,
    oauth_client,
    user_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    """
    Test ``GET /data/download/1`` with unauthenticated user.
    """
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "uploader": "fake_uploader_123",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000178"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()
    indexed_file_location = "s3"
    path = "/data/download/1"
    query_string = {"protocol": indexed_file_location}
    response = client.get(path, query_string=query_string)
    assert response.status_code == 401
    mock_index_document.stop()


def test_indexd_download_with_uploader_authorized(
    client,
    oauth_client,
    user_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    """
    Test ``GET /data/download/1`` with authorized user (user is the uploader).
    """
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "uploader": user_client.username,
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000178"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()
    indexed_file_location = "s3"
    path = "/data/download/1"
    query_string = {"protocol": indexed_file_location}
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    mock_index_document.stop()


@pytest.mark.parametrize("indexd_client", ["s3_assume_role"], indirect=True)
@pytest.mark.parametrize("presigned_url_expires_in", [100, 1000])
@pytest.mark.parametrize(
    "test_max_role_session_increase, test_assume_role_cache_seconds",
    [(True, 100), (True, 1800), (False, 0)],
)
def test_assume_role_time_limit(
    client,
    user_client,
    kid,
    rsa_private_key,
    test_max_role_session_increase,
    test_assume_role_cache_seconds,
    presigned_url_expires_in,
    indexd_client,
    monkeypatch,
):
    """
    Test ``GET /data/download/1`` accessing data from bucket by assuming role.
    """

    fence.S3IndexedFileLocation._assume_role_cache.clear()

    monkeypatch.setitem(
        config, "MAX_ROLE_SESSION_INCREASE", test_max_role_session_increase
    )
    monkeypatch.setitem(
        config, "ASSUME_ROLE_CACHE_SECONDS", test_assume_role_cache_seconds
    )
    duration_in_function = 0

    def mock_sts_client_assume_role(RoleArn, DurationSeconds, RoleSessionName=None):
        nonlocal duration_in_function
        duration_in_function = DurationSeconds
        return {
            "Credentials": {
                "AccessKeyId": "",
                "SecretAccessKey": "",
                "SessionToken": "",
                "Expiration": datetime.now() + timedelta(seconds=DurationSeconds),
            },
            "AssumedRoleUser": {"AssumedRoleId": "", "Arn": RoleArn},
        }

    with patch("fence.resources.aws.boto_manager.client") as mocked_sts_client:
        mocked_sts_client.return_value = MagicMock(
            assume_role=mock_sts_client_assume_role
        )
        indexed_file_location = indexd_client["indexed_file_location"]
        path = "/data/download/1"
        query_string = {
            "protocol": indexed_file_location,
            "expires_in": presigned_url_expires_in,
        }
        headers = {
            "Authorization": "Bearer "
            + jwt.encode(
                utils.authorized_download_context_claims(
                    user_client.username, user_client.user_id
                ),
                key=rsa_private_key,
                headers={"kid": kid},
                algorithm="RS256",
            )
        }
        response = client.get(path, headers=headers, query_string=query_string)

    AWS_ASSUME_ROLE_MIN_EXPIRATION = 900

    buffered_expires_in = presigned_url_expires_in
    if config["MAX_ROLE_SESSION_INCREASE"]:
        buffered_expires_in += int(config["ASSUME_ROLE_CACHE_SECONDS"])
    buffered_expires_in = max(buffered_expires_in, AWS_ASSUME_ROLE_MIN_EXPIRATION)

    assert response.status_code == 200
    assert duration_in_function == buffered_expires_in  # assume role duration
    assert (
        "X-Amz-Expires=" + str(presigned_url_expires_in) + "&" in response.json["url"]
    )  # Signed url duration


def test_assume_role_cache(
    client,
    oauth_client,
    user_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1`` with authorized user (user is the uploader).
    """

    assume_role_called = 0

    def mock_assume_role(self, role_arn, duration_seconds, config=None):
        nonlocal assume_role_called
        assume_role_called += 1
        return {
            "Credentials": {
                "AccessKeyId": "",
                "SecretAccessKey": "",
                "SessionToken": "",
                "Expiration": datetime.now() + timedelta(seconds=duration_seconds),
            },
            "AssumedRoleUser": {"AssumedRoleId": "", "Arn": role_arn},
        }

    assume_role_patcher = patch(
        "fence.resources.aws.boto_manager.BotoManager.assume_role", mock_assume_role
    )
    assume_role_patcher.start()

    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "uploader": user_client.username,
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket5/key-{}".format(did[:8])],
        "acl": ["phs000178"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()
    indexed_file_location = "s3"
    path = "/data/download/1"
    query_string = {"protocol": indexed_file_location}
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }

    # initial call
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert assume_role_called == 1

    # in-memory cache
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert assume_role_called == 1

    # use database cache if in-memory cache is missing
    fence.S3IndexedFileLocation._assume_role_cache.clear()
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert assume_role_called == 1

    # use database cache if in-memory cache is expired
    arn, vals = list(fence.S3IndexedFileLocation._assume_role_cache.items())[0]
    fence.S3IndexedFileLocation._assume_role_cache[arn] = vals[0], time.time() - 10
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert assume_role_called == 1

    # in-memory cache is missing and database cache is expired
    fence.S3IndexedFileLocation._assume_role_cache.clear()
    import flask

    with flask.current_app.db.session as session:
        session.execute(
            "UPDATE assume_role_cache SET expires_at = :ts", dict(ts=time.time() - 10)
        )
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert assume_role_called == 2

    assume_role_patcher.stop()
    mock_index_document.stop()


def test_indexd_download_with_uploader_unauthorized(
    client,
    oauth_client,
    user_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    """
    Test ``GET /data/download/1`` with unauthorized user (user is not the uploader).
    """
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "uploader": "fake_uploader_123",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000178"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()
    indexed_file_location = "s3"
    path = "/data/download/1"
    query_string = {"protocol": indexed_file_location}
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 401
    mock_index_document.stop()


def test_delete_file_no_auth(app, client, encoded_creds_jwt):
    """
    Test that a request to delete data files using a JWT which is valid but missing
    delete permission fails with 403.
    """
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000178"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()
    headers = {"Authorization": "Bearer " + encoded_creds_jwt.jwt}
    with mock.patch("fence.blueprints.data.indexd.requests.put"):
        response = client.delete("/data/{}".format(did), headers=headers)
        assert response.status_code == 403
    mock_index_document.stop()


def test_delete_file_locations(
    app, client, encoded_creds_jwt, user_client, monkeypatch
):
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "authz": ["/programs/phs000178"],
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000178"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )
    mock_indexed_file_delete_file = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.delete_files",
        mock.MagicMock(return_value=("", 204)),
    )
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_check_auth = mock.patch.object(
        fence.blueprints.data.indexd.IndexedFile,
        "check_legacy_authorization",
        return_value=True,
    )

    mock_index_document.start()
    mock_indexed_file_delete_file.start()
    mock_check_auth.start()
    mock_boto_delete = mock.MagicMock()
    monkeypatch.setattr(app.boto, "delete_data_file", mock_boto_delete)

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    mock_delete_response = mock.MagicMock()
    mock_delete_response.status_code = 200
    mock_delete = mock.MagicMock(requests.put, return_value=mock_delete_response)
    with mock.patch(
        "fence.blueprints.data.indexd.requests.delete", mock_delete
    ), arborist_requests_mocker as arborist_requests:
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        headers = {"Authorization": "Bearer " + encoded_creds_jwt.jwt}
        response = client.delete("/data/{}".format(did), headers=headers)
        assert response.status_code == 204
        assert mock_boto_delete.called_once()

    mock_check_auth.stop()
    mock_index_document.stop()
    mock_indexed_file_delete_file.stop()


def test_delete_file_locations_by_uploader(
    app, client, encoded_creds_jwt, user_client, monkeypatch
):
    did = str(uuid.uuid4())
    index_document = {
        "did": did,
        "baseid": "",
        "rev": "",
        "uploader": user_client.username,
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key-{}".format(did[:8])],
        "acl": ["phs000178"],
        "hashes": {},
        "metadata": {},
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_indexed_file_delete_file = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.delete_files",
        mock.MagicMock(return_value=("", 204)),
    )
    mock_check_auth = mock.patch.object(
        fence.blueprints.data.indexd.IndexedFile,
        "check_legacy_authorization",
        return_value=True,
    )

    class FakeGCM(object):
        def __enter__(self):
            return self

        def __exit__(self, a, b, c):
            return

        def delete_data_file(self, bucket, file_id):
            return "", 200

    mock_gcm = mock.patch(
        "fence.blueprints.data.indexd.GoogleCloudManager", return_value=FakeGCM()
    )

    mock_index_document.start()
    mock_indexed_file_delete_file.start()
    mock_check_auth.start()
    mock_boto_delete = mock.MagicMock()
    monkeypatch.setattr(app.boto, "delete_data_file", mock_boto_delete)

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    mock_delete_response = mock.MagicMock()
    mock_delete_response.status_code = 200
    mock_delete = mock.MagicMock(requests.put, return_value=mock_delete_response)
    with mock.patch(
        "fence.blueprints.data.indexd.requests.delete", mock_delete
    ), arborist_requests_mocker as arborist_requests, mock_gcm as mock_gcm_2:
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        headers = {"Authorization": "Bearer " + encoded_creds_jwt.jwt}
        response = client.delete("/data/{}".format(did), headers=headers)
        assert response.status_code == 204
        assert mock_boto_delete.called_once()

    mock_check_auth.stop()
    mock_index_document.stop()
    mock_indexed_file_delete_file.stop()


def test_blank_index_upload_unauthorized(
    app,
    client,
    auth_client,
    encoded_creds_jwt,
    user_client,
    aws_signed_url,
):
    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        # pretend arborist says "no"
        arborist_requests.return_value = MockResponse({"auth": False})
        arborist_requests.return_value.status_code = 200
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        data = json.dumps({"file_name": "doesn't matter"})
        response = client.post("/data/upload", headers=headers, data=data)
        data_requests.post.assert_not_called()
        assert response.status_code == 403, response


def test_blank_index_upload_failed(
    app,
    client,
    auth_client,
    encoded_creds_jwt,
    user_client,
    aws_signed_url,
):
    """Test that data/upload does not return a pre-signed url if blank creation failed."""

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        # user is authorized by arborist
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        data = json.dumps({"file_name": "doesn't matter"})
        # failure from indexd create blank record
        data_requests.return_value.status_code = 500

        response = client.post("/data/upload", headers=headers, data=data)

        data_requests.post.assert_called()
        # assert that we do not get a pre-signed url
        assert response.status_code == 500, response


def test_blank_index_upload_missing_did(
    app,
    client,
    auth_client,
    encoded_creds_jwt,
    user_client,
    aws_signed_url,
):
    """
    Test that data/upload does not return a pre-signed url
    if blank creation does not have a 'did' key.
    """

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        # user is authorized by arborist
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        data = json.dumps({"file_name": "doesn't matter"})
        data_requests.return_value.status_code = 200
        # Missing 'did' in response.
        data_requests.post.return_value = MockResponse(
            {
                "baseid": str(uuid.uuid4()),
            }
        )

        response = client.post("/data/upload", headers=headers, data=data)

        data_requests.post.assert_called()
        # assert that we do not get a pre-signed url
        assert response.status_code == 500, response


@pytest.mark.parametrize(
    "indexd_client_with_arborist",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external"],
    indirect=True,
)
def test_abac(
    app,
    client,
    mock_arborist_requests,
    indexd_client_with_arborist,
    user_client,
    rsa_private_key,
    kid,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    aws_signed_url,
):
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    indexd_client = indexd_client_with_arborist("test_abac")
    indexed_file_location = indexd_client["indexed_file_location"]
    path = "/data/download/1"
    query_string = {"protocol": indexed_file_location}
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())

    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": False}, 403)}})
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 403


def test_initialize_multipart_upload(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )

    fence.blueprints.data.indexd.BlankIndex.init_multipart_upload = MagicMock()
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        data_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        data_requests.post.return_value.status_code = 200
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        fence.blueprints.data.indexd.BlankIndex.init_multipart_upload.return_value = (
            "test_uploadId"
        )
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        data = json.dumps({"file_name": file_name})
        response = client.post("/data/multipart/init", headers=headers, data=data)
        indexd_url = app.config.get("INDEXD") or app.config.get("BASE_URL") + "/index"
        endpoint = indexd_url + "/index/blank/"
        indexd_auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
        data_requests.post.assert_called_once_with(
            endpoint,
            auth=indexd_auth,
            json={"file_name": file_name, "uploader": user_client.username},
            headers={},
        )
        assert response.status_code == 201, response
        assert "guid" in response.json
        assert "uploadId" in response.json


def test_initialize_multipart_upload_with_guid_in_request(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    Test /data/multipart/init with guid parameter in request data
    """

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )

    fence.blueprints.data.indexd.BlankIndex.init_multipart_upload = MagicMock()
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        did = str(uuid.uuid4())
        data_requests.get.return_value = MockResponse(
            {
                "did": did,
                "baseid": "",
                "rev": "",
                "size": 10,
                "file_name": "file1",
                "urls": ["s3://bucket1/key"],
                "hashes": {},
                "metadata": {},
                "authz": ["/open"],
                "acl": ["*"],
                "form": "",
                "created_date": "",
                "updated_date": "",
            }
        )
        data_requests.get.return_value.status_code = 200

        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        fence.blueprints.data.indexd.BlankIndex.init_multipart_upload.return_value = (
            "test_uploadId"
        )
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        data = json.dumps({"file_name": file_name, "guid": did})
        response = client.post("/data/multipart/init", headers=headers, data=data)

        assert response.status_code == 201, response
        assert "guid" in response.json
        assert did == response.json.get("guid")
        assert "uploadId" in response.json


def test_initialize_multipart_upload_with_non_existent_guid_in_request(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    Test /data/multipart/init with guid parameter in request data but no guid exist in indexd
    """

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )

    fence.blueprints.data.indexd.BlankIndex.init_multipart_upload = MagicMock()
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        did = str(uuid.uuid4())
        data_requests.get.return_value = MockResponse("no record found")
        data_requests.get.return_value.status_code = 404
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        fence.blueprints.data.indexd.BlankIndex.init_multipart_upload.return_value = (
            "test_uploadId"
        )
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        data = json.dumps({"file_name": file_name, "guid": did})
        response = client.post("/data/multipart/init", headers=headers, data=data)

        assert response.status_code == 404, response


def test_multipart_upload_presigned_url(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )

    fence.blueprints.data.indexd.BlankIndex.generate_aws_presigned_url_for_part = (
        MagicMock()
    )
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        data_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        data_requests.post.return_value.status_code = 200
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        fence.blueprints.data.indexd.BlankIndex.generate_aws_presigned_url_for_part.return_value = (
            "test_presigned"
        )
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        key = "guid/asdf"
        uploadid = "uploadid"

        data = json.dumps({"key": key, "uploadId": uploadid, "partNumber": 1})
        response = client.post("/data/multipart/upload", headers=headers, data=data)

        assert response.status_code == 200, response
        assert "presigned_url" in response.json


def test_multipart_complete_upload(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )

    fence.blueprints.data.indexd.BlankIndex.complete_multipart_upload = MagicMock()
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        data_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        data_requests.post.return_value.status_code = 200
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        fence.blueprints.data.indexd.BlankIndex.generate_aws_presigned_url_for_part.return_value = (
            "test_presigned"
        )
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        key = "guid/asdf"
        uploadid = "uploadid"

        data = json.dumps(
            {
                "key": key,
                "uploadId": uploadid,
                "parts": [{"partNumber": 1, "Etag": "test_tag"}],
            }
        )
        response = client.post("/data/multipart/complete", headers=headers, data=data)

        assert response.status_code == 200, response


def test_initialize_multipart_upload_with_bucket_param(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    Test /data/multipart/init containing bucket parameter
    """

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )

    fence.blueprints.data.indexd.BlankIndex.init_multipart_upload = MagicMock()
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        data_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        data_requests.post.return_value.status_code = 200
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        fence.blueprints.data.indexd.BlankIndex.init_multipart_upload.return_value = (
            "test_uploadId"
        )
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        data = json.dumps({"file_name": file_name, "bucket": "bucket3"})
        response = client.post("/data/multipart/init", headers=headers, data=data)
        indexd_url = app.config.get("INDEXD") or app.config.get("BASE_URL") + "/index"
        endpoint = indexd_url + "/index/blank/"
        indexd_auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
        data_requests.post.assert_called_once_with(
            endpoint,
            auth=indexd_auth,
            json={"file_name": file_name, "uploader": user_client.username},
            headers={},
        )
        assert response.status_code == 201, response
        assert "guid" in response.json
        assert "uploadId" in response.json


def test_multipart_upload_presigned_url_with_bucket_param(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    Test /data/multipart/upload containing bucket parameter
    """

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )

    fence.blueprints.data.indexd.BlankIndex.generate_aws_presigned_url_for_part = (
        MagicMock()
    )
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        data_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        data_requests.post.return_value.status_code = 200
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        fence.blueprints.data.indexd.BlankIndex.generate_aws_presigned_url_for_part.return_value = (
            "test_presigned"
        )
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        key = "guid/asdf"
        uploadid = "uploadid"

        data = json.dumps(
            {"key": key, "uploadId": uploadid, "partNumber": 1, "bucket": "bucket3"}
        )
        response = client.post("/data/multipart/upload", headers=headers, data=data)

        assert response.status_code == 200, response
        assert "presigned_url" in response.json


def test_multipart_complete_upload_with_bucket_param(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    Test /data/multipart/complete containing bucket parameter
    """

    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )

    fence.blueprints.data.indexd.BlankIndex.complete_multipart_upload = MagicMock()
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        data_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        data_requests.post.return_value.status_code = 200
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        fence.blueprints.data.indexd.BlankIndex.generate_aws_presigned_url_for_part.return_value = (
            "test_presigned"
        )
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        key = "guid/asdf"
        uploadid = "uploadid"

        data = json.dumps(
            {
                "key": key,
                "uploadId": uploadid,
                "bucket": "bucket3",
                "parts": [{"partNumber": 1, "Etag": "test_tag"}],
            }
        )
        response = client.post("/data/multipart/complete", headers=headers, data=data)

        assert response.status_code == 200, response


def test_delete_files(app, client, auth_client, encoded_creds_jwt, user_client):
    fence.auth.config["MOCK_AUTH"] = True
    did = str(uuid.uuid4())
    did2 = str(uuid.uuid4())

    indx = fence.blueprints.data.indexd.IndexedFile(did)
    urls = [
        "s3://bucket1/key-{}".format(did[:8]),
        "s3://bucket1/key-{}".format(did2[:8]),
    ]
    with patch("fence.blueprints.data.indexd.S3IndexedFileLocation") as s3mock:
        s3mock.return_value.bucket_name.return_value = "bucket"
        s3mock.return_value.file_name.return_value = "file"
        mocklocation = s3mock.return_value

        # no urls, no files, no error
        mocklocation.delete.return_value = ("ok", 200)
        indx.indexed_file_locations = []
        message, status = indx.delete_files(urls=None, delete_all=True)
        assert 0 == mocklocation.delete.call_count
        assert status == 200

        # urls, files, no error
        mocklocation.reset_mock()
        indx.indexed_file_locations = [mocklocation, mocklocation]
        message, status = indx.delete_files(urls, delete_all=True)
        assert 2 == mocklocation.delete.call_count
        assert status == 200

        # no urls, files, no error
        mocklocation.reset_mock()
        message, status = indx.delete_files(urls=None)
        assert 2 == mocklocation.delete.call_count
        assert status == 200

        # case for urls subset of total locations without error
        mocklocation.reset_mock()
        urls = ["s3://bucket1/key-{}".format(did2[:8])]
        message, status = indx.delete_files(urls, delete_all=True)
        assert 1 == mocklocation.delete.call_count
        assert status == 200

        # no urls, files, error
        mocklocation.reset_mock()
        mocklocation.delete.return_value = ("bad response", 400)
        message, status = indx.delete_files(urls=None, delete_all=True)
        assert 1 == mocklocation.delete.call_count
        assert status == 400

        # urls, files, error
        mocklocation.reset_mock()
        message, status = indx.delete_files(urls)
        assert 1 == mocklocation.delete.call_count
        assert status == 400

        # case for urls subset of total locations with error
        mocklocation.reset_mock()
        message, status = indx.delete_files(urls, delete_all=True)
        assert 1 == mocklocation.delete.call_count
        assert status == 400

    fence.auth.config["MOCK_AUTH"] = False


def test_download_s3_file_with_client_token(
    client,
    indexd_client_accepting_record,
    kid,
    rsa_private_key,
    mock_arborist_requests,
    monkeypatch,
):
    """
    Test that an access token that does not include a `sub` or `context.user.
    name` (such as a token issued from the `client_credentials` flow) can be
    used to download data from S3 if the indexd_record has an `authz` field,
    and that the `client_id` is used to sign.
    """
    indexd_record = {
        **INDEXD_RECORD_WITH_PUBLIC_AUTHZ_POPULATED,
        "did": "guid_for:test_download_file_with_client_token",
        "authz": ["/test/resource/path"],
        "urls": ["s3://bucket1/key"],
    }
    indexd_client_accepting_record(indexd_record)
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    client_credentials_token = utils.client_authorized_download_context_claims()
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            client_credentials_token,
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }

    # the config for the client credentials should have already been set
    assert isinstance(config.get("CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED"), bool)

    # download should fail when client is disabled
    monkeypatch.setitem(config, "CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED", False)
    assert config["CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED"] == False
    response = client.get("/data/download/1", headers=headers)
    assert response.status_code == 403

    # download should succeed when client is enabled
    monkeypatch.setitem(config, "CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED", True)
    assert config["CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED"] == True
    response = client.get("/data/download/1", headers=headers)
    assert response.status_code == 200

    signed_url = response.json.get("url")
    assert signed_url
    # check signing query parameters
    query_params = urllib.parse.parse_qs(signed_url)
    assert query_params.get("user_id") == [ANONYMOUS_USER_ID]
    assert query_params.get("username") == [ANONYMOUS_USERNAME]
    assert query_params.get("client_id") == [client_credentials_token["azp"]]
