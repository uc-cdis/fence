import jwt
import mock
import pytest

from fence.config import config
from tests import utils


class MockResponse(object):
    def __init__(self, data, status_code=200):
        self.data = data
        self.status_code = status_code


@pytest.mark.parametrize("indexd_client_with_arborist", ["s3_and_gs"], indirect=True)
@pytest.mark.parametrize("protocol", ["gs", None])
def test_presigned_url_log(
    protocol,
    client,
    user_client,
    mock_arborist_requests,
    indexd_client_with_arborist,
    kid,
    rsa_private_key,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    monkeypatch,
):
    """
    Get a presigned URL from Fence and make sure a call to the Audit Service
    was made to create an audit log. Test with and without a requested
    protocol.
    """
    mock_arborist_requests(
        {"arborist/auth/request": {"POST": ('{"auth": "true"}', 200)}}
    )
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    guid = "dg.hello/abc"
    path = f"/data/download/{guid}"
    resource_paths = ["/my/resource/path1", "/path2"]
    indexd_client = indexd_client_with_arborist(resource_paths)
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

    # protocol=None should fall back to s3 (first indexed location):
    expected_protocol = protocol or "s3"

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(
            path, headers=headers, query_string={"protocol": protocol}
        )
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/presigned_url",
            json={
                "request_url": path,
                "status_code": 200,
                "username": user_client.username,
                "sub": user_client.user_id,
                "guid": guid,
                "resource_paths": resource_paths,
                "action": "download",
                "protocol": expected_protocol,
            },
        )
    assert response.status_code == 200
    assert response.json.get("url")


@pytest.mark.parametrize(
    "indexd_client_with_arborist", ["s3_and_gs_acl_no_authz"], indirect=True
)
def test_presigned_url_log_acl(
    client,
    user_client,
    mock_arborist_requests,
    indexd_client_with_arborist,
    kid,
    rsa_private_key,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    monkeypatch,
):
    """
    Same as `test_presigned_url_log`, but the record contains `acl` instead
    of `authz`. The ACL is ["phs000178", "phs000218"] as defined in conftest.
    """
    mock_arborist_requests(
        {"arborist/auth/request": {"POST": ('{"auth": "true"}', 200)}}
    )
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    protocol = "gs"
    guid = "dg.hello/abc"
    path = f"/data/download/{guid}"
    indexd_client = indexd_client_with_arborist(None)
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

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(
            path, headers=headers, query_string={"protocol": protocol}
        )
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/presigned_url",
            json={
                "request_url": path,
                "status_code": 200,
                "username": user_client.username,
                "sub": user_client.user_id,
                "guid": guid,
                "resource_paths": ["phs000178", "phs000218"],
                "action": "download",
                "protocol": protocol,
            },
        )
    assert response.status_code == 200
    assert response.json.get("url")


@pytest.mark.parametrize("public_indexd_client", ["s3_and_gs"], indirect=True)
def test_presigned_url_log_public(client, public_indexd_client, monkeypatch):
    """
    Same as `test_presigned_url_log`, but with an anonymous user downloading
    public data.
    """
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    guid = "dg.hello/abc"
    path = f"/data/download/{guid}"

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path)
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/presigned_url",
            json={
                "request_url": path,
                "status_code": 200,
                "username": "anonymous",
                "sub": None,
                "guid": guid,
                "resource_paths": [],
                "action": "download",
                "protocol": "s3",
            },
        )
    assert response.status_code == 200
    assert response.json.get("url")


# TODO login logs
