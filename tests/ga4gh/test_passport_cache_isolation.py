"""
A GA4GH passport cache entry is keyed by one passport's hash and is trusted without
re-validation when it is hit again, so an entry must describe only the identities that
that passport itself asserts.
"""

import hashlib
import json
import time
from unittest.mock import patch

import flask
import httpx
import jwt
import responses

from gen3authz.client.arborist.client import ArboristClient

from fence.config import config
from fence.models import GA4GHPassportCache
from tests.conftest import NoAsyncMagicMock


USER_A_SUB = "user-a-sub-0001"
USER_B_SUB = "user-b-sub-0002"
ISSUER = "https://stsstg.nih.gov"

USER_A_USERNAME = USER_A_SUB + ISSUER[len("https://") :]
USER_B_USERNAME = USER_B_SUB + ISSUER[len("https://") :]

INDEXD_RECORD = {
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


def _encode_passport(sub, private_key, kid, current_time, phs_id):
    """Build a signed passport carrying one signed dbGaP visa for `sub`."""
    decoded_visa = {
        "iss": ISSUER,
        "sub": sub,
        "iat": current_time,
        "exp": current_time + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": f"jti-{sub}",
        "txn": f"txn-{sub}",
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
                "phs_id": phs_id,
                "version": "v1",
                "participant_set": "p1",
                "consent_group": "c1",
                "role": "designated user",
                "expiration": current_time + 1000,
            }
        ],
    }
    encoded_visa = jwt.encode(
        decoded_visa, key=private_key, headers={"kid": kid}, algorithm="RS256"
    )

    passport = {
        "iss": ISSUER,
        "sub": sub,
        "iat": current_time,
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": current_time + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }
    return jwt.encode(
        passport,
        key=private_key,
        headers={"type": "JWT", "alg": "RS256", "kid": kid},
        algorithm="RS256",
    )


def _passport_hash(encoded_passport):
    """The cache key for an encoded passport."""
    return hashlib.sha256(encoded_passport.encode("utf-8")).hexdigest()


@responses.activate
@patch("httpx.get")
@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
def test_cache_entry_holds_only_its_own_passports_users(
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
    Submitting two passports in one request caches each one against only its own user.

    If an entry accumulated the other passport's identity, that passport alone would
    later stand in for both users, since a cache hit skips re-validation.
    """
    passport_cache = {}
    from fence.resources.ga4gh import passports as passports_module

    monkeypatch.setattr(passports_module, "PASSPORT_CACHE", passport_cache)
    db_session.query(GA4GHPassportCache).delete()
    db_session.commit()

    monkeypatch.setitem(config, "GA4GH_PASSPORTS_TO_DRS_ENABLED", True)
    indexd_client_accepting_record(INDEXD_RECORD)
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    mock_arborist.return_value = NoAsyncMagicMock(ArboristClient)
    mock_google_proxy_group.return_value = google_proxy_group

    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    now = int(time.time())
    user_a_passport = _encode_passport(
        USER_A_SUB, rsa_private_key, kid, now, "phs000991"
    )
    user_b_passport = _encode_passport(
        USER_B_SUB, rsa_private_key, kid, now, "phs000961"
    )

    usernames = passports_module.sync_gen3_users_authz_from_ga4gh_passports(
        [user_a_passport, user_b_passport],
        db_session=db_session,
    )
    assert set(usernames) == {USER_A_USERNAME, USER_B_USERNAME}

    cached_by_hash = {
        row.passport_hash: row.user_ids
        for row in db_session.query(GA4GHPassportCache).all()
    }

    for encoded_passport, expected_username in (
        (user_a_passport, USER_A_USERNAME),
        (user_b_passport, USER_B_USERNAME),
    ):
        entry_hash = _passport_hash(encoded_passport)
        assert cached_by_hash.get(entry_hash) == [expected_username]

        in_memory_entry = passport_cache.get(entry_hash)
        assert in_memory_entry
        assert list(in_memory_entry[0]) == [expected_username]
