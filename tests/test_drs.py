import flask
import httpx
import hashlib
import json
import jwt
import pytest
import requests
import responses
from tests import utils
from tests.conftest import NoAsyncMagicMock
import time
from unittest.mock import MagicMock, patch

from gen3authz.client.arborist.client import ArboristClient

from fence.config import config
from fence.models import GA4GHPassportCache
from tests.utils import add_test_ras_user, TEST_RAS_USERNAME, TEST_RAS_SUB


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
        )
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
        )
    }

    res = client.get(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/",
        headers=user,
    )
    assert res.status_code == 400

    res = client.get(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access",
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
        )
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
        )
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
        )
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
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
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
                "consent_group": "c999",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

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
    )

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
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
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
                "consent_group": "c999",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

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
    )

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
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
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
                "consent_group": "c999",
                "role": "designated user",
                "expiration": int(time.time()) + 1001,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

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
    )

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
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
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
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
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


@responses.activate
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_passport_cache_valid_passport(
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
    db_session,
    monkeypatch,
):
    """
    Test that when a passport is provided a second time, the in-memory cache gets used
    and the database cache is populated.

    NOTE: This is very similar to the test_get_presigned_url_for_non_public_data_with_passport
          test with added stuff to check cache functionality
    """
    # reset caches
    PASSPORT_CACHE = {}
    from fence.resources.ga4gh import passports as passports_module

    monkeypatch.setattr(passports_module, "PASSPORT_CACHE", PASSPORT_CACHE)
    db_session.query(GA4GHPassportCache).delete()
    db_session.commit()

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
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    # Prepare Passport/Visa
    current_time = int(time.time())
    headers = {"kid": kid}
    decoded_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": current_time,
        "exp": current_time + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1.1",
            "asserted": current_time,
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
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "General Research Use (IRB, PUB)",
                "phs_id": "phs000961",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Cardiovascular Disease)",
                "phs_id": "phs000279",
                "version": "v2",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Health/Medical/Biomedical (IRB)",
                "phs_id": "phs000286",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c3",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Focused Disease Only, IRB, NPU)",
                "phs_id": "phs000289",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c2",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Autism Spectrum Disorder)",
                "phs_id": "phs000298",
                "version": "v4",
                "participant_set": "p3",
                "consent_group": "c999",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": current_time,
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": current_time + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }
    encoded_passport = jwt.encode(
        passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    )

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = [encoded_passport]

    data = {"passports": passports}

    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    passport_hash = hashlib.sha256(encoded_passport.encode("utf-8")).hexdigest()

    # check database cache
    cached_passports = [
        item.passport_hash for item in db_session.query(GA4GHPassportCache).all()
    ]
    assert passport_hash not in cached_passports

    # check in-memory cache
    assert not PASSPORT_CACHE.get(passport_hash)

    before_cache_start = time.time()
    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    before_cache_end = time.time()
    before_cache_time = before_cache_end - before_cache_start
    assert res.status_code == 200

    # check that database cache populated
    cached_passports = [
        item.passport_hash for item in db_session.query(GA4GHPassportCache).all()
    ]
    assert passport_hash in cached_passports

    # check that in-memory cache populated
    assert PASSPORT_CACHE.get(passport_hash)

    after_cache_start = time.time()
    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    after_cache_end = time.time()
    after_cache_time = after_cache_end - after_cache_start
    assert res.status_code == 200
    # make sure using the cache is faster
    # assert after_cache_time < before_cache_time


@responses.activate
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_passport_cache_invalid_passport(
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
    db_session,
    monkeypatch,
):
    """
    Test that when an invalid passport is provided a second time, the in-memory cache
    does NOT get used and the database cache is NOT populated.

    NOTE: This is very similar to the test_get_presigned_url_for_non_public_data_with_passport
          test with added stuff to check cache functionality
    """
    # reset caches
    PASSPORT_CACHE = {}
    from fence.resources.ga4gh import passports as passports_module

    monkeypatch.setattr(passports_module, "PASSPORT_CACHE", PASSPORT_CACHE)
    db_session.query(GA4GHPassportCache).delete()
    db_session.commit()

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
        "acl": [""],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": False}, 200)}})
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    # Prepare Passport/Visa
    current_time = int(time.time())
    headers = {"kid": kid}
    decoded_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": current_time,
        "exp": current_time + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1.1",
            "asserted": current_time,
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
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "General Research Use (IRB, PUB)",
                "phs_id": "phs000961",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Cardiovascular Disease)",
                "phs_id": "phs000279",
                "version": "v2",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Health/Medical/Biomedical (IRB)",
                "phs_id": "phs000286",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c3",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Focused Disease Only, IRB, NPU)",
                "phs_id": "phs000289",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c2",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Autism Spectrum Disorder)",
                "phs_id": "phs000298",
                "version": "v4",
                "participant_set": "p3",
                "consent_group": "c999",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": current_time,
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": current_time + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }
    invalid_encoded_passport = "invalid" + jwt.encode(
        passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    )

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = [invalid_encoded_passport]

    data = {"passports": passports}

    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    passport_hash = hashlib.sha256(invalid_encoded_passport.encode("utf-8")).hexdigest()

    # check database cache
    cached_passports = [
        item.passport_hash for item in db_session.query(GA4GHPassportCache).all()
    ]
    assert passport_hash not in cached_passports

    # check in-memory cache
    assert not PASSPORT_CACHE.get(passport_hash)

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code != 200

    # check that database cache NOT populated
    cached_passports = [
        item.passport_hash for item in db_session.query(GA4GHPassportCache).all()
    ]
    assert passport_hash not in cached_passports

    # check that in-memory cache NOT populated
    assert not PASSPORT_CACHE.get(passport_hash)

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code != 200


@responses.activate
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_passport_cache_expired_in_memory_valid_in_db(
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
    db_session,
    monkeypatch,
):
    """
    Test that when a passport is provided a second time when the the in-memory cache
    is expired but the database cache is valid, we still get a successful response.

    Check that cached database is updated and placed in in-memory cache.

    NOTE: This is very similar to the test_get_presigned_url_for_non_public_data_with_passport
          test with added stuff to check cache functionality
    """
    # reset cache
    # PASSPORT_CACHE = {}
    from fence.resources.ga4gh import passports as passports_module

    # monkeypatch.setattr(passports_module, "PASSPORT_CACHE", PASSPORT_CACHE)
    db_session.query(GA4GHPassportCache).delete()
    db_session.commit()

    # # add test user
    # test_user = add_test_ras_user(db_session=db_session)
    # test_user.username = "abcd-asdj-sajpiasj12iojd-asnoinstsstg.nih.gov"
    test_username = "abcd-asdj-sajpiasj12iojd-asnoinstsstg.nih.gov"
    # mocked_method = MagicMock(return_value=test_user)
    # patch_method = patch(
    #     "fence.resources.ga4gh.passports.query_for_user", mocked_method
    # )
    # patch_method.start()

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
        "acl": [""],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    # Prepare Passport/Visa
    current_time = int(time.time())
    headers = {"kid": kid}
    decoded_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": current_time,
        "exp": current_time + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1.1",
            "asserted": current_time,
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
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "General Research Use (IRB, PUB)",
                "phs_id": "phs000961",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Cardiovascular Disease)",
                "phs_id": "phs000279",
                "version": "v2",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Health/Medical/Biomedical (IRB)",
                "phs_id": "phs000286",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c3",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Focused Disease Only, IRB, NPU)",
                "phs_id": "phs000289",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c2",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
            {
                "consent_name": "Disease-Specific (Autism Spectrum Disorder)",
                "phs_id": "phs000298",
                "version": "v4",
                "participant_set": "p3",
                "consent_group": "c999",
                "role": "designated user",
                "expiration": current_time + 1000,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": current_time,
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": current_time + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }
    encoded_passport = jwt.encode(
        passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    )

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = [encoded_passport]

    data = {"passports": passports}

    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    passport_hash = hashlib.sha256(encoded_passport.encode("utf-8")).hexdigest()

    # simulate db cache with a valid passport by first calling the endpoint to cache
    # res = client.post(
    #     "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
    #     headers={
    #         "Content-Type": "application/json",
    #     },
    #     data=json.dumps(data),
    # )
    # assert res.status_code == 200
    passports_module.put_gen3_usernames_for_passport_into_cache(
        encoded_passport, [test_username], current_time + 1000, db_session=db_session
    )

    # double-check database cache
    cached_passport = (
        db_session.query(GA4GHPassportCache)
        .filter(GA4GHPassportCache.passport_hash == passport_hash)
        .first()
    )
    # greater and NOT == b/c of logic to set internal expiration less than real to allow
    # time for expiration job to run
    assert cached_passport and cached_passport.expires_at > current_time

    # simulate in-memory cache with an expired passport by overriding the in-memory cache
    from fence.resources.ga4gh import passports as passports_module

    PASSPORT_CACHE = {f"{passport_hash}": ([test_username], current_time - 1)}
    assert PASSPORT_CACHE.get(passport_hash, ("", 0))[1] == current_time - 1
    monkeypatch.setattr(passports_module, "PASSPORT_CACHE", PASSPORT_CACHE)

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code == 200

    # check that database cache still populated
    assert (
        len([item.passport_hash for item in db_session.query(GA4GHPassportCache).all()])
        == 1
    )
    cached_passport = (
        db_session.query(GA4GHPassportCache)
        .filter(GA4GHPassportCache.passport_hash == passport_hash)
        .first()
    )
    # greater and NOT == b/c of logic to set internal expiration less than real to allow
    # time for expiration job to run
    assert cached_passport and cached_passport.expires_at > current_time

    # check that in-memory cache populated with db expiration
    # greater and NOT == b/c of logic to set internal expiration less than real to allow
    # time for expiration job to run
    if PASSPORT_CACHE.get(passport_hash, ("", 0))[1] == 0:
        from fence.resources.ga4gh.passports import PASSPORT_CACHE as import_cache

        assert PASSPORT_CACHE == None
    assert PASSPORT_CACHE.get(passport_hash, ("", 0))[1] > current_time


@responses.activate
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_passport_cache_expired(
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
    db_session,
    monkeypatch,
):
    """
    Test that when a passport is expired, we don't get a successful response, even
    if the passport was previously cached.

    NOTE: This is very similar to the test_get_presigned_url_for_non_public_data_with_passport
          test with added stuff to check cache functionality
    """
    # reset cache
    PASSPORT_CACHE = {}
    from fence.resources.ga4gh import passports as passports_module

    monkeypatch.setattr(passports_module, "PASSPORT_CACHE", PASSPORT_CACHE)
    db_session.query(GA4GHPassportCache).delete()
    db_session.commit()

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
        "acl": [""],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    # Prepare Passport/Visa
    current_time = int(time.time())
    headers = {"kid": kid}
    decoded_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": current_time,
        "exp": current_time + 2,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1.1",
            "asserted": current_time,
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
                "expiration": current_time + 2,
            },
            {
                "consent_name": "General Research Use (IRB, PUB)",
                "phs_id": "phs000961",
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 2,
            },
            {
                "consent_name": "Disease-Specific (Cardiovascular Disease)",
                "phs_id": "phs000279",
                "version": "v2",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 2,
            },
            {
                "consent_name": "Health/Medical/Biomedical (IRB)",
                "phs_id": "phs000286",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c3",
                "role": "designated user",
                "expiration": current_time + 2,
            },
            {
                "consent_name": "Disease-Specific (Focused Disease Only, IRB, NPU)",
                "phs_id": "phs000289",
                "version": "v6",
                "participant_set": "p2",
                "consent_group": "c2",
                "role": "designated user",
                "expiration": current_time + 2,
            },
            {
                "consent_name": "Disease-Specific (Autism Spectrum Disorder)",
                "phs_id": "phs000298",
                "version": "v4",
                "participant_set": "p3",
                "consent_group": "c999",
                "role": "designated user",
                "expiration": current_time + 2,
            },
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": current_time,
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": current_time + 2,
        "ga4gh_passport_v1": [encoded_visa],
    }
    encoded_passport = jwt.encode(
        passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    )

    access_id = indexd_client["indexed_file_location"]
    test_guid = "1"

    passports = [encoded_passport]

    data = {"passports": passports}

    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    passport_hash = hashlib.sha256(encoded_passport.encode("utf-8")).hexdigest()

    # check database cache
    cached_passports = [
        item.passport_hash for item in db_session.query(GA4GHPassportCache).all()
    ]
    assert passport_hash not in cached_passports

    # check in-memory cache
    assert not PASSPORT_CACHE.get(passport_hash)

    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code == 200

    # ensure passport is expired by sleeping
    expire_time = current_time + 2
    current_time = int(time.time())
    if current_time < expire_time:
        sleep_time = expire_time - current_time
        time.sleep(sleep_time)

    # try again
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": False}, 200)}})
    res = client.post(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id,
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
    )
    assert res.status_code != 200


@pytest.mark.parametrize("indexd_client", ["s3", "gs"], indirect=True)
def test_get_presigned_url_with_client_token(
    client,
    indexd_client,
    indexd_client_accepting_record,
    kid,
    rsa_private_key,
    mock_arborist_requests,
    monkeypatch,
):
    """
    Test that a client credentials token (without using passports)
    can be used to get a pre-signed url.
    """
    test_guid = "1"
    access_id = indexd_client["indexed_file_location"]
    indexd_record = {
        "did": test_guid,
        "authz": ["/test/resource/path"],
        "urls": ["s3://bucket1/key", "gs://bucket1/key"],
    }
    indexd_client_accepting_record(indexd_record)
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    client_credentials_token = utils.client_authorized_download_context_claims()
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            client_credentials_token,
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        )
    }

    # the config for the client credentials should have already been set
    assert isinstance(config.get("CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED"), bool)

    # download should fail when client is disabled
    monkeypatch.setitem(config, "CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED", False)
    assert config["CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED"] == False
    response = client.get("/data/download/" + test_guid, headers=headers)
    assert response.status_code == 403

    # download should succeed when client is enabled
    monkeypatch.setitem(config, "CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED", True)
    assert config["CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED"] == True
    response = client.get(
        "/ga4gh/drs/v1/objects/" + test_guid + "/access/" + access_id, headers=headers
    )
    assert response.status_code == 200

    signed_url = response.json.get("url")
    assert signed_url
