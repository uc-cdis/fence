import json
import mock
import urlparse
import uuid

import jwt
import pytest
import requests

import fence.blueprints.data.indexd
from fence.config import config
from fence.errors import NotSupported

from tests import utils


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
        )
    }
    response = client.get(path, headers=headers, query_string=query_string)
    print(response.json)
    assert response.status_code == 200
    assert "url" in response.json.keys()


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
    indexed_file_location = indexd_client["indexed_file_location"]
    path = "/data/upload/1?protocol=" + indexed_file_location
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
    assert "url" in response.json.keys()


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
        )
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert "url" in response.json.keys()


def test_indexd_download_file_no_jwt(client, auth_client):
    """
    Test ``GET /data/download/1``.
    """
    path = "/data/download/1"
    response = client.get(path)
    assert response.status_code == 401

    # response should not be JSON, should be HTML error page
    with pytest.raises(ValueError):
        response.json


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
    with pytest.raises(ValueError):
        response.json


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
    with pytest.raises(ValueError):
        response.json


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
    with pytest.raises(ValueError):
        response.json


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
    with pytest.raises(ValueError):
        response.json


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
    Test ``GET /data/upload/1``.
    """
    path = "/data/download/1"
    response = client.get(path)
    print(response.json)
    assert response.status_code == 200
    assert "url" in response.json.keys()


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
    print(response.json)
    assert response.status_code == 200
    url = response.json["url"]
    # public url without signature
    assert urlparse.urlparse(url).query == ""


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
    with pytest.raises(ValueError):
        response.json


def test_blank_index_upload(app, client, auth_client, encoded_creds_jwt, user_client):
    class MockResponse(object):
        def __init__(self, data, status_code=200):
            self.data = data
            self.status_code = status_code

        def json(self):
            return self.data

    with mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    ) as mock_requests:
        mock_requests.post.return_value = MockResponse(
            {
                "did": str(uuid.uuid4()),
                "rev": str(uuid.uuid4())[:8],
                "baseid": str(uuid.uuid4()),
            }
        )
        mock_requests.post.return_value.status_code = 200
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
        mock_requests.post.assert_called_once_with(
            endpoint,
            auth=indexd_auth,
            json={"file_name": file_name, "uploader": user_client.username},
        )
        assert response.status_code == 201, response
        assert "guid" in response.json
        assert "url" in response.json


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
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_check_auth = mock.patch.object(
        fence.blueprints.data.indexd.IndexedFile,
        "check_authorization",
        return_value=True,
    )
    mock_index_document.start()
    mock_check_auth.start()
    mock_boto_delete = mock.MagicMock()
    monkeypatch.setattr(app.boto, "delete_data_file", mock_boto_delete)

    mock_delete_response = mock.MagicMock()
    mock_delete_response.status_code = 200
    mock_delete = mock.MagicMock(requests.put, return_value=mock_delete_response)
    with mock.patch("fence.blueprints.data.indexd.requests.delete", mock_delete):
        headers = {"Authorization": "Bearer " + encoded_creds_jwt.jwt}
        response = client.delete("/data/{}".format(did), headers=headers)
        assert response.status_code == 204
        assert mock_boto_delete.called_once()

    mock_check_auth.stop()
    mock_index_document.stop()
