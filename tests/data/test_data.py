import json
import mock
import urllib.parse
import uuid

import jwt
import pytest
import requests

import fence.blueprints.data.indexd
from fence.config import config
from fence.errors import NotSupported

from tests import utils

from unittest.mock import MagicMock, patch

import cirrus
from cirrus import GoogleCloudManager


@pytest.mark.parametrize(
    "indexd_client", ["gs", "s3", "gs_acl", "s3_acl", "s3_external"], indirect=True
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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())

    # defaults to signing url, check that it's not just raw url
    assert urllib.parse.urlparse(response.json["url"]).query != ""


@pytest.mark.parametrize(
    "indexd_client", ["gs", "s3", "gs_acl", "s3_acl", "s3_external"], indirect=True
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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())
    assert file_id in response.json.get("url")


@pytest.mark.parametrize(
    "indexd_client", ["gs", "s3", "gs_acl", "s3_acl", "s3_external"], indirect=True
)
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
):
    """
    Test ``GET /data/download/1``.
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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())
    assert file_name in response.json.get("url")


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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers)

    assert response.status_code == 401


@pytest.mark.parametrize(
    "indexd_client", ["gs", "s3", "gs_acl", "s3_acl", "s3_external"], indirect=True
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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())


@pytest.mark.parametrize(
    "indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
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
    "indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
)
def test_indexd_unauthorized_download_file(
    client,
    oauth_client,
    unauthorized_user_client,
    indexd_client,
    cloud_manager,
    google_signed_url,
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
    "indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json

    mock_index_document.stop()


@pytest.mark.parametrize(
    "indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json

    mock_index_document.stop()


@pytest.mark.parametrize(
    "unauthorized_indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    assert response.mimetype == "text/html"
    assert not response.json

    mock_index_document.stop()


@pytest.mark.parametrize(
    "public_indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
)
def test_public_object_download_file(
    client,
    auth_client,
    public_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
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
    "public_indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
)
def test_public_object_download_file_no_force_sign(
    client,
    auth_client,
    public_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    """
    Test ``GET /data/download/1?no_force_sign=True``.
    """
    path = "/data/download/1?no_force_sign=True"
    response = client.get(path)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())

    # make sure we honor no_force_sign, check that response is unsigned raw url
    assert urllib.parse.urlparse(response.json["url"]).query == ""


@pytest.mark.parametrize(
    "public_bucket_indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
)
def test_public_bucket_download_file(
    client,
    auth_client,
    public_bucket_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    """
    Test ``GET /data/upload/1`` with public bucket
    """
    path = "/data/download/1"
    response = client.get(path)
    assert response.status_code == 200
    assert response.json.get("url")

    # we should NOT sign AWS S3 urls if the bucket itself is public
    if not public_bucket_indexd_client.startswith("s3"):
        # defaults to signing url, check that it's not just raw url
        assert urllib.parse.urlparse(response.json["url"]).query != ""


@pytest.mark.parametrize(
    "public_bucket_indexd_client", ["gs", "s3", "gs_acl", "s3_acl"], indirect=True
)
def test_public_bucket_download_file_no_force_sign(
    client,
    auth_client,
    public_bucket_indexd_client,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
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


def test_blank_index_upload(app, client, auth_client, encoded_creds_jwt, user_client):
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
        "gen3authz.client.arborist.client.requests.request", new_callable=mock.Mock
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
        assert response.status_code == 201, response
        assert "guid" in response.json
        assert "url" in response.json


def test_blank_index_upload_authz(
    app, client, auth_client, encoded_creds_jwt, user_client
):
    """
    Same test as above, except request a specific "authz" for the new record
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
        "gen3authz.client.arborist.client.requests.request", new_callable=mock.Mock
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
        indexd_auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
        data_requests.post.assert_called_once_with(
            endpoint,
            auth=None,
            json={"file_name": file_name, "uploader": None, "authz": authz},
            headers={"Authorization": "bearer " + encoded_creds_jwt.jwt},
        )
        assert response.status_code == 201, response
        assert "guid" in response.json
        assert "url" in response.json


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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200


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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 401


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
        "gen3authz.client.arborist.client.requests", new_callable=mock.Mock
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
        "check_authorization",
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
        arborist_requests.request.return_value = MockResponse({"auth": True})
        arborist_requests.request.return_value.status_code = 200
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
        "gen3authz.client.arborist.client.requests", new_callable=mock.Mock
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
        "check_authorization",
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
        arborist_requests.request.return_value = MockResponse({"auth": True})
        arborist_requests.request.return_value.status_code = 200
        headers = {"Authorization": "Bearer " + encoded_creds_jwt.jwt}
        response = client.delete("/data/{}".format(did), headers=headers)
        assert response.status_code == 204
        assert mock_boto_delete.called_once()

    mock_check_auth.stop()
    mock_index_document.stop()
    mock_indexed_file_delete_file.stop()


def test_blank_index_upload_unauthorized(
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
        "gen3authz.client.arborist.client.requests.request", new_callable=mock.Mock
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
):
    mock_arborist_requests(
        {"arborist/auth/request": {"POST": ('{"auth": "true"}', 200)}}
    )
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
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert "url" in list(response.json.keys())

    mock_arborist_requests(
        {"arborist/auth/request": {"POST": ('{"auth": "false"}', 403)}}
    )
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
        "gen3authz.client.arborist.client.requests.request", new_callable=mock.Mock
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
        "gen3authz.client.arborist.client.requests.request", new_callable=mock.Mock
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
        "gen3authz.client.arborist.client.requests.request", new_callable=mock.Mock
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
