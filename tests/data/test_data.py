import json
import mock
import urlparse
import uuid

import jwt
import pytest

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
        data = json.dumps({"file_name": "asdf"})
        response = client.post("/data/upload", headers=headers, data=data)
        indexd_url = app.config.get("INDEXD") or app.config.get("BASE_URL") + "/index"
        endpoint = indexd_url + "/index/blank"
        auth = ("gdcapi", "")
        mock_requests.post.assert_called_once_with(endpoint, auth=auth, json=mock.ANY)
        # assert_called_once_with cannot handle multiple items in json
        _, call_kwargs = mock_requests.post.call_args
        assert call_kwargs["json"] == {"uploader": "test", "file_name": "asdf"}

        assert response.status_code == 201, response
        assert "guid" in response.json
        assert "url" in response.json
