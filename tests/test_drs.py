import flask
import httpx
import json
import jwt
import pytest
import requests
import responses
from tests import utils
import time
from unittest.mock import MagicMock, patch

from gen3authz.client.arborist.client import ArboristClient

from fence.config import config


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


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_passport_use_disabled(
    mock_arborist,
    mock_google_proxy_group,
    mock_httpx_get,
    client,
    indexd_client,
    kid,
    rsa_private_key,
    rsa_public_key,
    indexd_client_accepting_record,
    mock_arborist_requests,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    config["GA4GH_PASSPORTS_TO_DRS_ENABLED"] = False
    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "did": "1",
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key", "gs://bucket1/key"],
        "hashes": {},
        "metadata": {},
        "authz": ["/orgA/programs/phs000991.c1"],
        "acl": ["*"],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    mock_arborist.return_value = MagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    # Prepare Passport/Visa
    headers = {"kid": kid}
    decoded_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "exp": int(time.time()) + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1.1",
            "asserted": int(time.time()),
            "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
            "source": "https://ncbi.nlm.nih.gov/gap",
        },
        "ras_dbgap_permissions": [
            {
                "consent_name": "Health/Medical/Biomedical",
                "phs_id": "phs000991",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "General Research Use (IRB, PUB)",
                "phs_id": "phs000961",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Cardiovascular Disease)",
                "phs_id": "phs000279",
                "version": "v2",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Health/Medical/Biomedical (IRB)",
                "phs_id": "phs000286",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c3",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Focused Disease Only, IRB, NPU)",
                "phs_id": "phs000289",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c2",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Autism Spectrum Disorder)",
                "phs_id": "phs000298",
                "version": "v4",
                "participant_set": "p3",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }
    encoded_passport = jwt.encode(
        passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    ).decode("utf-8")

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = [encoded_passport]

    data = {"passports": passports}

    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code == 400


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_get_presigned_url_for_non_public_data_with_passport(
    mock_arborist,
    mock_google_proxy_group,
    mock_httpx_get,
    client,
    indexd_client,
    kid,
    rsa_private_key,
    rsa_public_key,
    indexd_client_accepting_record,
    mock_arborist_requests,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    config["GA4GH_PASSPORTS_TO_DRS_ENABLED"] = True
    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "did": "1",
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key", "gs://bucket1/key"],
        "hashes": {},
        "metadata": {},
        "authz": ["/orgA/programs/phs000991.c1"],
        "acl": ["*"],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    mock_arborist.return_value = MagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    # Prepare Passport/Visa
    headers = {"kid": kid}
    decoded_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "exp": int(time.time()) + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1.1",
            "asserted": int(time.time()),
            "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
            "source": "https://ncbi.nlm.nih.gov/gap",
        },
        "ras_dbgap_permissions": [
            {
                "consent_name": "Health/Medical/Biomedical",
                "phs_id": "phs000991",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "General Research Use (IRB, PUB)",
                "phs_id": "phs000961",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Cardiovascular Disease)",
                "phs_id": "phs000279",
                "version": "v2",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Health/Medical/Biomedical (IRB)",
                "phs_id": "phs000286",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c3",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Focused Disease Only, IRB, NPU)",
                "phs_id": "phs000289",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c2",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Autism Spectrum Disorder)",
                "phs_id": "phs000298",
                "version": "v4",
                "participant_set": "p3",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }
    encoded_passport = jwt.encode(
        passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    ).decode("utf-8")

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = [encoded_passport]

    data = {"passports": passports}

    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code == 200


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_get_presigned_url_with_passport_with_incorrect_authz(
    mock_arborist,
    mock_google_proxy_group,
    mock_httpx_get,
    client,
    indexd_client,
    kid,
    rsa_private_key,
    rsa_public_key,
    indexd_client_accepting_record,
    mock_arborist_requests,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "did": "1",
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key", "gs://bucket1/key"],
        "hashes": {},
        "metadata": {},
        "authz": ["/orgA/programs/phs000991.c1"],
        "acl": ["*"],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": False}, 200)}})
    mock_arborist.return_value = MagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    # Prepare Passport/Visa
    headers = {"kid": kid}
    decoded_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "exp": int(time.time()) + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1.1",
            "asserted": int(time.time()),
            "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
            "source": "https://ncbi.nlm.nih.gov/gap",
        },
        "ras_dbgap_permissions": [
            {
                "consent_name": "Health/Medical/Biomedical",
                "phs_id": "phs000991",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "General Research Use (IRB, PUB)",
                "phs_id": "phs000961",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Cardiovascular Disease)",
                "phs_id": "phs000279",
                "version": "v2",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Health/Medical/Biomedical (IRB)",
                "phs_id": "phs000286",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c3",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Focused Disease Only, IRB, NPU)",
                "phs_id": "phs000289",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c2",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
            {
                "consent_name": "Disease-Specific (Autism Spectrum Disorder)",
                "phs_id": "phs000298",
                "version": "v4",
                "participant_set": "p3",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }
    encoded_passport = jwt.encode(
        passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    ).decode("utf-8")

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = [encoded_passport]

    data = {"passports": passports}

    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code == 401


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_get_presigned_url_for_public_data_with_no_passport(
    mock_arborist,
    mock_google_proxy_group,
    mock_httpx_get,
    client,
    indexd_client,
    kid,
    rsa_private_key,
    rsa_public_key,
    indexd_client_accepting_record,
    mock_arborist_requests,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    indexd_record_with_public_authz_and_public_acl_populated = {
        "did": "1",
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key", "gs://bucket1/key"],
        "hashes": {},
        "metadata": {},
        "authz": ["/open"],
        "acl": ["*"],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_public_authz_and_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    mock_arborist.return_value = MagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = []

    data = {"passports": passports}

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code == 200


@responses.activate
@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_get_presigned_url_for_non_public_data_with_no_passport(
    mock_arborist,
    mock_google_proxy_group,
    mock_httpx_get,
    client,
    indexd_client,
    kid,
    rsa_private_key,
    rsa_public_key,
    indexd_client_accepting_record,
    mock_arborist_requests,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    indexd_record_with_public_authz_and_non_public_acl_populated = {
        "did": "1",
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket1/key", "gs://bucket1/key"],
        "hashes": {},
        "metadata": {},
        "authz": ["/orgA/programs/phs000991.c1"],
        "acl": ["*"],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_public_authz_and_non_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": False}, 200)}})
    mock_arborist.return_value = MagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = []

    data = {"passports": passports}

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code == 401
