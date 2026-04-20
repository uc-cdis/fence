import json
import pytest
from unittest.mock import patch


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


def test_bulk_drs_access_happy_path(client, user_client):
    object_ids = ["guid1", "guid2"]

    mock_response = {
        "urls": [
            {"drs_object_id": "guid1", "url": "https://signed1"},
            {"drs_object_id": "guid2", "url": "https://signed2"},
        ],
        "failed_file_ids": [],
    }

    with patch(
        "fence.blueprints.ga4gh.bulk_get_signed_url_for_file",
        return_value=mock_response,
    ):
        response = client.post(
            "/ga4gh/drs/v1/objects/access",
            data=json.dumps(make_request_body(object_ids)),
            content_type="application/json",
            headers={"Authorization": f"Bearer {user_client.token}"},
        )

    assert response.status_code == 200
    data = json.loads(response.data)

    assert data["summary"]["requested"] == 2
    assert data["summary"]["resolved"] == 2
    assert data["summary"]["unresolved"] == 0

    assert len(data["resolved_drs_object_access_urls"]) == 2


def test_bulk_drs_access_partial_failure(client, user_client):
    object_ids = ["guid1", "guid2"]

    mock_response = {
        "urls": [
            {"drs_object_id": "guid1", "url": "https://signed1"},
        ],
        "failed_file_ids": [
            {"error_code": 403, "object_ids": ["guid2"]},
        ],
    }

    with patch(
        "fence.blueprints.ga4gh.bulk_get_signed_url_for_file",
        return_value=mock_response,
    ):
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


def test_bulk_drs_access_max_limit(client, user_client):
    object_ids = [f"guid{i}" for i in range(101)]  # exceed default 100

    response = client.post(
        "/ga4gh/drs/v1/objects/access",
        data=json.dumps(make_request_body(object_ids)),
        content_type="application/json",
        headers={"Authorization": f"Bearer {user_client.token}"},
    )

    assert response.status_code == 413
