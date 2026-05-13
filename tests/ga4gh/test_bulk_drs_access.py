import json
import pytest
import responses
from unittest.mock import patch, MagicMock


def make_request_body(object_ids, access_id="s3"):
    return {
        "passports": None,
        "bulk_object_access_ids": [
            {
                "bulk_object_id": obj_id,
                "bulk_access_ids": [access_id],
            }
            for obj_id in object_ids
        ],
    }


def mock_indexd_response(guid, authz="test_authz"):
    """Helper to create a mock indexd document response."""
    return {
        "did": guid,
        "urls": [f"s3://test-bucket/{guid}"],
        "authz": [authz],
        "size": 123,
        "hashes": {"md5": "abcd"},
    }


@pytest.fixture
def user_client():
    return {
        "username": "test",
        "user_id": 902,
        "token": "test-token",
    }


@responses.activate
def test_bulk_drs_access_happy_path(client, user_client):
    object_ids = ["guid1", "guid2"]

    # Mock indexd bulk endpoint
    responses.add(
        responses.POST,
        "http://indexd-service/index/bulk/documents",
        json=[mock_indexd_response(guid) for guid in object_ids],
        status=200,
    )

    # Mock authorization: allow access to "test_authz"
    mock_auth_mapping = {"test_authz": [{"service": "fence", "method": "read-storage"}]}

    with patch(
        "flask.current_app.arborist.auth_mapping", return_value=mock_auth_mapping
    ), patch("flask.current_app.arborist.auth_request", return_value=True), patch(
        "gen3cirrus.AwsService.download_presigned_url",
        return_value="https://signed-url",
    ) as mock_download:

        response = client.post(
            "/ga4gh/drs/v1/objects/access",
            data=json.dumps(make_request_body(object_ids)),
            content_type="application/json",
            headers={"Authorization": f"Bearer {user_client['token']}"},
        )
    print(response.data)

    assert response.status_code == 200
    data = json.loads(response.data)

    assert data["summary"]["requested"] == 2
    assert data["summary"]["resolved"] == 2
    assert data["summary"]["unresolved"] == 0

    assert len(data["resolved_drs_object_access_urls"]) == 2
    # Verify storage layer was called for each file
    assert mock_download.call_count == 2


@responses.activate
def test_bulk_drs_access_partial_failure(client, user_client):
    object_ids = ["guid1", "guid2"]

    # Mock indexd bulk endpoint - return both files with different authz
    responses.add(
        responses.POST,
        "http://indexd-service/index/bulk/documents",
        json=[
            mock_indexd_response("guid1", "allowed_authz"),
            mock_indexd_response("guid2", "denied_authz"),
        ],
        status=200,
    )

    # Mock authorization: allow "allowed_authz" but not "denied_authz"
    mock_auth_mapping = {
        "allowed_authz": [{"service": "fence", "method": "read-storage"}]
    }

    with patch(
        "flask.current_app.arborist.auth_mapping", return_value=mock_auth_mapping
    ), patch(
        "flask.current_app.arborist.auth_request",
        side_effect=lambda **kw: "allowed_authz" in str(kw.get("resources", [])),
    ), patch(
        "gen3cirrus.AwsService.download_presigned_url",
        side_effect=lambda *args, **kwargs: f"https://signed{args[1].split('/')[-1]}",
    ) as mock_download:

        response = client.post(
            "/ga4gh/drs/v1/objects/access",
            data=json.dumps(make_request_body(object_ids)),
            content_type="application/json",
            headers={"Authorization": f"Bearer {user_client.token}"},
        )

    assert response.status_code == 200
    data = json.loads(response.data)

    assert data["summary"]["requested"] == 2
    assert data["summary"]["resolved"] == 1
    assert data["summary"]["unresolved"] == 1

    assert len(data["resolved_drs_object_access_urls"]) == 1
    assert len(data["unresolved_drs_objects"]) == 1
    assert data["unresolved_drs_objects"][0]["error_code"] == 403
    # Verify storage layer was called only for the allowed file
    assert mock_download.call_count == 1


@responses.activate
def test_bulk_drs_access_max_limit(client, user_client):
    object_ids = [f"guid{i}" for i in range(101)]  # exceed default 100

    response = client.post(
        "/ga4gh/drs/v1/objects/access",
        data=json.dumps(make_request_body(object_ids)),
        content_type="application/json",
        headers={"Authorization": f"Bearer {user_client.token}"},
    )

    assert response.status_code == 413


@responses.activate
def test_bulk_drs_access_missing_guid(client, user_client):
    """Test that when some GUIDs are missing from indexd, only missing ones are marked as 404."""
    object_ids = ["guid1", "missing_guid"]

    # Mock indexd bulk endpoint - only return guid1 (missing_guid doesn't exist)
    responses.add(
        responses.POST,
        "http://indexd-service/index/bulk/documents",
        json=[mock_indexd_response("guid1", "test_authz")],
        status=200,
    )

    # Mock authorization
    mock_auth_mapping = {"test_authz": [{"service": "fence", "method": "read-storage"}]}

    with patch(
        "flask.current_app.arborist.auth_mapping", return_value=mock_auth_mapping
    ), patch("flask.current_app.arborist.auth_request", return_value=True), patch(
        "gen3cirrus.AwsService.download_presigned_url",
        side_effect=lambda *args, **kwargs: f"https://signed{args[1].split('/')[-1]}",
    ) as mock_download:

        response = client.post(
            "/ga4gh/drs/v1/objects/access",
            data=json.dumps(make_request_body(object_ids)),
            content_type="application/json",
            headers={"Authorization": f"Bearer {user_client.token}"},
        )

    assert response.status_code == 200
    data = json.loads(response.data)

    assert data["summary"]["requested"] == 2
    assert data["summary"]["resolved"] == 1
    assert data["summary"]["unresolved"] == 1

    assert len(data["resolved_drs_object_access_urls"]) == 1
    assert data["resolved_drs_object_access_urls"][0]["drs_object_id"] == "guid1"

    assert len(data["unresolved_drs_objects"]) == 1
    assert data["unresolved_drs_objects"][0]["error_code"] == 404
    assert "missing_guid" in data["unresolved_drs_objects"][0]["object_ids"]

    # Verify storage layer was only called for the existing file
    assert mock_download.call_count == 1
