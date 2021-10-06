import json
import jwt
import pytest
import requests
import responses
from tests import utils


def get_doc(has_version=True, urls=list(), drs_list=0):
    doc = {
        "form": "object",
        "size": 123,
        "urls": ["s3://endpointurl/bucket/key"],
        "hashes": {"md5": "1234"},
    }
    if has_version:
        doc["version"] = "1"
    if urls:
        doc["urls"] = urls

    return doc


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
def test_get_presigned_url_unauthorized(
    client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"
    user = {"Authorization": "Bearer INVALID"}

    res = client.get(
        "/ga4gh/drs/v1/objects/" + test_guid + f"/access/{access_id}",
        headers=user,
    )
    assert res.status_code == 401


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
def test_get_presigned_url_with_access_id(
    client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"
    user = {
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

    res = client.get(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers=user,
    )
    assert res.status_code == 200


@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
def test_get_presigned_url_no_access_id(
    client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"
    user = {
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

    res = client.get(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/",
        headers=user,
    )
    assert res.status_code == 400


@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
def test_get_presigned_url_no_bearer_token(
    client,
    indexd_client,
):
    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    res = client.get("/ga4gh/drs/v1/objects/" + test_guid + f"/access/{access_id}")
    assert res.status_code == 401


@responses.activate
def test_get_presigned_url_wrong_access_id(
    client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    test_guid = "1"
    user = {
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
    res = client.get(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/s2",
        headers=user,
    )
    assert res.status_code == 404


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
def test_get_presigned_url_with_encoded_slash(
    client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"
    user = {
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
    data = get_doc()
    data["did"] = "dg.TEST/ed8f4658-6acd-4f96-9dd8-3709890c959e"
    did = "dg.TEST%2Fed8f4658-6acd-4f96-9dd8-3709890c959e"

    res = client.get(
        "/ga4gh/drs/v1/objects/" + did + "/access/" + access_id,
        headers=user,
    )
    assert res.status_code == 200


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
def test_get_presigned_url_with_query_params(
    client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"
    user = {
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
    data = get_doc()
    data["did"] = "dg.TEST/ed8f4658-6acd-4f96-9dd8-3709890c959e"
    did = "dg.TEST%2Fed8f4658-6acd-4f96-9dd8-3709890c959e"

    res = client.get(
        "/ga4gh/drs/v1/objects/"
        + did
        + "/access/"
        + access_id
        + "?userProject=someproject&arbitrary_parameter=val",
        headers=user,
    )
    assert res.status_code == 200
