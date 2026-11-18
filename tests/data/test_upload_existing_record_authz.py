"""
`POST /data/upload` and `POST /data/multipart/init` accept a caller-supplied GUID. When
that GUID names a record that already exists, the upload that comes back writes to that
record's storage key, so the caller has to be authorized against that record - holding
the generic upload permission is not enough.
"""

import copy
import json

import mock
import pytest


EXISTING_RECORD_AUTHZ = "/programs/EXISTING_RECORD_PROGRAM"
UPLOAD_RESOURCE = "/data_file"

# Each upload endpoint that accepts a GUID, and the response field that proves the
# upload was handed out.
UPLOAD_ENDPOINTS = {
    "/data/upload": "url",
    "/data/multipart/init": "uploadId",
}

EXISTING_RECORD = {
    "did": "existing-guid",
    "rev": "abcd1234",
    "baseid": "base-id",
    "file_name": "existing_file.txt",
    "authz": [EXISTING_RECORD_AUTHZ],
    "acl": [],
    "urls": ["s3://bucket1/existing-guid/existing_file.txt"],
    "uploader": "someone_else",
    "hashes": {},
    "metadata": {},
    "size": 10,
    "form": "object",
    "created_date": "",
    "updated_date": "",
}


class MockResponse(object):
    """Mock response for the requests and httpx libraries."""

    def __init__(self, data, status_code=200):
        self.data = data
        self.status_code = status_code

    def json(self):
        return self.data

    def text(self):
        return self.data


def _arborist_allowing(allowed_resources):
    """
    Build an arborist stub that authorizes only the given resource paths.

    Answering per-resource keeps these tests honest: a stub that denied everything
    would also deny the generic upload check, so a 403 would not show that the
    record's own authz was consulted.

    Args:
        allowed_resources (set): resource paths to return ``auth: True`` for

    Returns:
        callable: a replacement for httpx.Client.request
    """

    def handle_request(*args, **kwargs):
        body = kwargs.get("json") or {}
        auth_requests = body.get("requests") or []
        if not auth_requests:
            return MockResponse({"auth": True}, 200)
        authorized = all(
            entry.get("resource") in allowed_resources for entry in auth_requests
        )
        return MockResponse({"auth": authorized}, 200)

    return handle_request


@pytest.fixture(params=sorted(UPLOAD_ENDPOINTS))
def upload_endpoint(request):
    """Each upload endpoint that accepts a caller-supplied GUID."""
    return request.param


def _post_upload_for_existing_guid(
    client, encoded_creds_jwt, record, allowed_resources, endpoint
):
    """Request an upload for an existing GUID from `endpoint` and return the response."""
    data_requests_mocker = mock.patch(
        "fence.blueprints.data.indexd.requests", new_callable=mock.Mock
    )
    arborist_requests_mocker = mock.patch(
        "gen3authz.client.arborist.client.httpx.Client.request", new_callable=mock.Mock
    )
    multipart_init_mocker = mock.patch(
        "fence.blueprints.data.indexd.BlankIndex.init_multipart_upload",
        return_value="test-upload-id",
    )
    with data_requests_mocker as data_requests, arborist_requests_mocker as arborist_requests, (
        multipart_init_mocker
    ):
        data_requests.get.return_value = MockResponse(record)
        data_requests.get.return_value.status_code = 200
        arborist_requests.side_effect = _arborist_allowing(allowed_resources)

        return client.post(
            endpoint,
            headers={
                "Authorization": "Bearer " + encoded_creds_jwt.jwt,
                "Content-Type": "application/json",
            },
            data=json.dumps({"file_name": record["file_name"], "guid": record["did"]}),
        )


def test_upload_denied_without_permission_on_the_existing_record(
    app,
    client,
    auth_client,
    encoded_creds_jwt,
    user_client,
    aws_signed_url,
    upload_endpoint,
):
    """A caller with only the generic upload permission cannot target another record."""
    response = _post_upload_for_existing_guid(
        client,
        encoded_creds_jwt,
        EXISTING_RECORD,
        allowed_resources={UPLOAD_RESOURCE},
        endpoint=upload_endpoint,
    )

    assert response.status_code == 403


def test_upload_allowed_with_permission_on_the_existing_record(
    app,
    client,
    auth_client,
    encoded_creds_jwt,
    user_client,
    aws_signed_url,
    upload_endpoint,
):
    """A caller authorized on the record's authz may request its upload URL."""
    response = _post_upload_for_existing_guid(
        client,
        encoded_creds_jwt,
        EXISTING_RECORD,
        allowed_resources={UPLOAD_RESOURCE, EXISTING_RECORD_AUTHZ},
        endpoint=upload_endpoint,
    )

    assert response.status_code == 201
    assert UPLOAD_ENDPOINTS[upload_endpoint] in response.json


def test_upload_to_unauthz_record_denied_for_other_uploader(
    app,
    client,
    auth_client,
    encoded_creds_jwt,
    user_client,
    aws_signed_url,
    upload_endpoint,
):
    """With no authz on the record, a caller who is not the uploader is refused."""
    record = copy.deepcopy(EXISTING_RECORD)
    record["authz"] = []
    record["uploader"] = "someone_else"

    response = _post_upload_for_existing_guid(
        client,
        encoded_creds_jwt,
        record,
        allowed_resources={UPLOAD_RESOURCE},
        endpoint=upload_endpoint,
    )

    assert response.status_code == 403


def test_upload_to_unauthz_record_allowed_for_its_uploader(
    app,
    client,
    auth_client,
    encoded_creds_jwt,
    user_client,
    aws_signed_url,
    upload_endpoint,
):
    """
    With no authz on the record, its own uploader may still request an upload URL.

    This is the blank-record flow: a record created by this user carries `uploader`
    and no authz, and re-requesting its upload URL has to keep working.
    """
    record = copy.deepcopy(EXISTING_RECORD)
    record["authz"] = []
    record["uploader"] = user_client.username

    response = _post_upload_for_existing_guid(
        client,
        encoded_creds_jwt,
        record,
        allowed_resources={UPLOAD_RESOURCE},
        endpoint=upload_endpoint,
    )

    assert response.status_code == 201
    assert UPLOAD_ENDPOINTS[upload_endpoint] in response.json
