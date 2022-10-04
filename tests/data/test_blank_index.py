"""
Test fence.blueprints.data.indexd.BlankIndex
"""
import json
import uuid
import copy

from unittest.mock import MagicMock

import mock
from mock import patch
import pytest

from fence.config import config
from fence.blueprints.data.indexd import BlankIndex, flask
from fence.errors import InternalError


class MockResponse:
    """
    Mock response for requests lib
    """

    def __init__(self, data, status_code=200):
        """
        Set up mock response
        """
        self.data = data
        self.status_code = status_code

    def json(self):
        """
        Mock json() call
        """
        return self.data

    def text(self):
        """
        Mock text() call
        """
        return self.data


def test_blank_index_upload(app, client, auth_client, encoded_creds_jwt, user_client):
    """
    test BlankIndex upload
    POST /data/upload
    """
    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
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
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        data = json.dumps({"file_name": file_name})
        response = client.post("/data/upload", headers=headers, data=data)
        indexd_url = app.config.get("INDEXD") or app.config.get("BASE_URL") + "/index"
        endpoint = indexd_url + "/index/blank/"
        indexd_auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
        data_requests.post.assert_called_once_with(
            endpoint,
            auth=indexd_auth,
            json={"file_name": file_name, "uploader": user_client.username},
            headers={},
        )
        assert response.status_code == 201, response.json
        assert "guid" in response.json
        assert "url" in response.json


def test_blank_index_upload_authz(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    Same test as above, except request a specific "authz" for the new record
    """
    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
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
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        authz = ["/test1/test1", "/test2/test3/test4"]
        data = json.dumps({"file_name": file_name, "authz": authz})
        response = client.post("/data/upload", headers=headers, data=data)
        indexd_url = app.config.get("INDEXD") or app.config.get("BASE_URL") + "/index"
        endpoint = indexd_url + "/index/blank/"
        data_requests.post.assert_called_once_with(
            endpoint,
            auth=None,
            json={"file_name": file_name, "uploader": None, "authz": authz},
            headers={"Authorization": "bearer " + encoded_creds_jwt.jwt},
        )
        assert response.status_code == 201, response.json
        assert "guid" in response.json
        assert "url" in response.json


@pytest.mark.parametrize(
    "bucket,expected_status_code",
    [
        # fallback to default DATA_UPLOAD_BUCKET
        [None, 201],
        # bucket configured in S3_BUCKETS AND in ALLOWED_DATA_UPLOAD_BUCKETS
        ["bucket3", 201],
        # bucket configured in S3_BUCKETS but NOT in ALLOWED_DATA_UPLOAD_BUCKETS
        ["bucket2", 403],
        # bucket NOT configured in S3_BUCKETS or ALLOWED_DATA_UPLOAD_BUCKETS
        ["not-a-configured-bucket", 403],
    ],
)
def test_blank_index_upload_bucket(
    app,
    client,
    auth_client,
    encoded_creds_jwt,
    user_client,
    bucket,
    expected_status_code,
):
    """
    Same test as above, except request a specific bucket to upload the file to
    """
    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
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
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        data = json.dumps({"file_name": file_name, "bucket": bucket})
        response = client.post("/data/upload", headers=headers, data=data)
        indexd_url = app.config.get("INDEXD") or app.config.get("BASE_URL") + "/index"
        endpoint = indexd_url + "/index/blank/"
        indexd_auth = (
            config["INDEXD_USERNAME"],
            config["INDEXD_PASSWORD"],
        )
        data_requests.post.assert_called_once_with(
            endpoint,
            auth=indexd_auth,
            json={"file_name": file_name, "uploader": user_client.username},
            headers={},
        )

        assert response.status_code == expected_status_code, response.json
        if expected_status_code == 201:
            assert "guid" in response.json
            assert "url" in response.json
            bucket_in_url = bucket if bucket else config["DATA_UPLOAD_BUCKET"]
            assert bucket_in_url in response.json["url"]


def test_blank_index_upload_missing_indexd_credentials(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    test BlankIndex upload with missing indexd credentials
    """
    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        data_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        data_requests.post.return_value.status_code = 401
        arborist_requests.return_value = MockResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        data = json.dumps({"file_name": file_name})
        response = client.post("/data/upload", headers=headers, data=data)
        indexd_url = app.config.get("INDEXD") or app.config.get("BASE_URL") + "/index"
        endpoint = indexd_url + "/index/blank/"
        indexd_auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
        data_requests.post.assert_called_once_with(
            endpoint,
            auth=indexd_auth,
            json={"file_name": file_name, "uploader": user_client.username},
            headers={},
        )
        assert response.status_code == 500, response
        assert not response.json


def test_blank_index_upload_missing_indexd_credentials_unable_to_load_json(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    test BlankIndex upload call but unable to load json with a ValueError
    """

    class MockArboristResponse:
        """
        Mock response for requests lib for Arborist
        """

        def __init__(self, data, status_code=200):
            """
            Set up mock response
            """
            self.data = data
            self.status_code = status_code

        def json(self):
            """
            Mock json() call
            """
            return self.data

    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests:
        data_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        data_requests.post.return_value.status_code = 401
        arborist_requests.return_value = MockArboristResponse({"auth": True})
        arborist_requests.return_value.status_code = 200
        headers = {
            "Authorization": "Bearer " + encoded_creds_jwt.jwt,
            "Content-Type": "application/json",
        }
        file_name = "asdf"
        data = json.dumps({"file_name": file_name})
        response = client.post("/data/upload", headers=headers, data=data)
        indexd_url = app.config.get("INDEXD") or app.config.get("BASE_URL") + "/index"
        endpoint = indexd_url + "/index/blank/"
        indexd_auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
        data_requests.post.assert_called_once_with(
            endpoint,
            auth=indexd_auth,
            json={"file_name": file_name, "uploader": user_client.username},
            headers={},
        )
        assert response.status_code == 500, response
        assert not response.json


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_blank_index_set_uploader(app, indexd_client):
    """
    Test BlankIndex with an uploader
    """
    uploader = MagicMock()
    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        blank_index = BlankIndex(uploader=uploader)
        assert blank_index


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_init_multipart_upload(app, indexd_client):
    """
    Test BlankIndex init_multipart_upload
    """
    uploader = MagicMock()
    blank_index = BlankIndex(uploader=uploader)
    assert blank_index
    with patch(
        "fence.blueprints.data.indexd.S3IndexedFileLocation.init_multipart_upload"
    ):
        blank_index.init_multipart_upload(key="some key")


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_init_multipart_upload_missing_configuration_key(app, indexd_client):
    """
    test BlankIndex init_multipart_upload with a missing configuration key
    """
    uploader = MagicMock()
    current_app = flask.current_app
    expected_value = copy.deepcopy(current_app.config)
    del expected_value["DATA_UPLOAD_BUCKET"]

    with patch.object(current_app, "config", expected_value):
        assert current_app.config == expected_value
        blank_index = BlankIndex(uploader=uploader)
        assert blank_index
        with pytest.raises(InternalError):
            blank_index.init_multipart_upload(key="some key")


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_complete_multipart_upload(app, indexd_client):
    """
    Test BlankIndex complete_multipart_upload
    """
    uploader = MagicMock()
    blank_index = BlankIndex(uploader=uploader)
    assert blank_index
    with patch(
        "fence.blueprints.data.indexd.S3IndexedFileLocation.complete_multipart_upload"
    ):
        blank_index.complete_multipart_upload(
            key="some key",
            uploadId="some id",
            parts=[
                {"Etag": "1234567", "PartNumber": 1},
                {"Etag": "4321234", "PartNumber": 2},
            ],
        )


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_complete_multipart_upload_missing_key(app, indexd_client):
    """
    Test BlankIndex complete_multipart_upload with a missing configuration key
    """
    uploader = MagicMock()
    current_app = flask.current_app
    expected_value = copy.deepcopy(current_app.config)
    del expected_value["DATA_UPLOAD_BUCKET"]

    with patch.object(current_app, "config", expected_value):
        assert current_app.config == expected_value
        blank_index = BlankIndex(uploader=uploader)
        assert blank_index
        with pytest.raises(InternalError):
            blank_index.complete_multipart_upload(
                key="some key",
                uploadId="some id",
                parts=[
                    {"Etag": "1234567", "PartNumber": 1},
                    {"Etag": "4321234", "PartNumber": 2},
                ],
            )


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_generate_aws_presigned_url_for_part(app, indexd_client):
    """
    Test BlankIndex generate_aws_presigned_url_for_part
    """
    uploader = MagicMock()
    blank_index = BlankIndex(uploader=uploader)
    assert blank_index
    with patch(
        "fence.blueprints.data.indexd.S3IndexedFileLocation.generate_presigned_url_for_part_upload"
    ):
        blank_index.generate_aws_presigned_url_for_part(
            key="some key", uploadId="some id", partNumber=1, expires_in=10
        )


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_generate_aws_presigned_url_for_part_missing_key(app, indexd_client):
    """
    Test BlankIndex generate_aws_presigned_url_for_part with a missing configuration key
    """
    uploader = MagicMock()
    current_app = flask.current_app
    expected_value = copy.deepcopy(current_app.config)
    del expected_value["DATA_UPLOAD_BUCKET"]

    with patch.object(current_app, "config", expected_value):
        assert current_app.config == expected_value
        blank_index = BlankIndex(uploader=uploader)
        assert blank_index
        with pytest.raises(InternalError):
            blank_index.generate_aws_presigned_url_for_part(
                key="some key", uploadId="some id", partNumber=1, expires_in=10
            )


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_make_signed_url(app, indexd_client):
    """
    Test BlankIndex make_signed_url with a missing configuration key
    """
    uploader = MagicMock()
    indexed_file_location = indexd_client["indexed_file_location"]

    blank_index = BlankIndex(uploader=uploader)
    assert blank_index
    with patch(
        "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation.get_signed_url"
    ):
        with patch("fence.blueprints.data.indexd.S3IndexedFileLocation.get_signed_url"):
            signed_url = blank_index.make_signed_url(
                file_name="some file name", protocol=indexed_file_location
            )


@pytest.mark.parametrize(
    "indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "s3_external", "az", "https"],
    indirect=True,
)
def test_make_signed_url_missing_configuration_key(app, indexd_client):
    """
    Test BlankIndex make_signed_url with a missing configuration key
    """
    uploader = MagicMock()
    current_app = flask.current_app
    expected_value = copy.deepcopy(current_app.config)
    del expected_value["AZ_BLOB_CONTAINER_URL"]
    del expected_value["DATA_UPLOAD_BUCKET"]

    indexed_file_location = indexd_client["indexed_file_location"]
    with patch.object(current_app, "config", expected_value):
        assert current_app.config == expected_value
        blank_index = BlankIndex(uploader=uploader)
        assert blank_index
        with patch(
            "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation.get_signed_url"
        ):
            with patch(
                "fence.blueprints.data.indexd.S3IndexedFileLocation.get_signed_url"
            ):
                with pytest.raises(InternalError):
                    signed_url = blank_index.make_signed_url(
                        file_name="some file name", protocol=indexed_file_location
                    )
