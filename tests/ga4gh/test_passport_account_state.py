"""
Resolving a visa identity to a Fence user grants that user's access and refreshes their
arborist policies, so it has to honor the same account-state decisions the login path
makes: a deactivated account stays deactivated, and a deployment that does not admit
new users on login does not gain them here either.
"""

import time
from unittest.mock import patch

import httpx
import jwt
import pytest

from fence.config import config
from fence.errors import Unauthorized
from fence.models import GA4GHPassportCache, query_for_user
from fence.resources.ga4gh import passports as passports_module
from fence.resources.ga4gh.passports import (
    get_or_create_gen3_user_from_iss_sub,
    put_gen3_usernames_for_passport_into_cache,
    sync_gen3_users_authz_from_ga4gh_passports,
)


ISSUER = "https://stsstg.nih.gov"
SUBJECT_ID = "account-state-subject"
USERNAME = SUBJECT_ID + ISSUER[len("https://") :]
DEACTIVATED_SUBJECT_ID = "deactivated-subject"


def _encode_passport(sub, private_key, kid, current_time):
    """Build a signed passport carrying one signed visa for `sub`."""
    visa = {
        "iss": ISSUER,
        "sub": sub,
        "iat": current_time,
        "exp": current_time + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1.1",
            "asserted": current_time,
            "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
            "source": "https://ncbi.nlm.nih.gov/gap",
        },
    }
    passport = {
        "iss": ISSUER,
        "sub": sub,
        "iat": current_time,
        "exp": current_time + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "ga4gh_passport_v1": [
            jwt.encode(visa, key=private_key, headers={"kid": kid}, algorithm="RS256")
        ],
    }
    return jwt.encode(
        passport, key=private_key, headers={"kid": kid}, algorithm="RS256"
    )


@pytest.fixture
def cached_passport_for_user(app, db_session, monkeypatch):
    """
    Create the visa identity's user and cache a passport as already resolving to them.

    The cached passport is not a valid JWT: a cache hit is trusted without
    re-validation, so anything that falls through to full validation is discarded.
    That makes the result show whether the cache alone resolved the user.
    """
    monkeypatch.setattr(passports_module, "PASSPORT_CACHE", {})
    db_session.query(GA4GHPassportCache).delete()
    db_session.commit()

    passport = "previously-validated-passport"
    with app.app_context():
        user = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )
        put_gen3_usernames_for_passport_into_cache(
            passport=passport,
            user_ids_from_passports=[USERNAME],
            expires_at=int(time.time()) + 1000,
            db_session=db_session,
        )
        db_session.commit()
    return passport, user


def test_new_user_is_created_when_allowed(app, db_session):
    """With new users allowed on login, an unseen visa identity gets an account."""
    with app.app_context():
        user = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )

    assert user.username == USERNAME


def test_existing_active_user_is_returned(app, db_session):
    """An active account is resolved on a later request."""
    with app.app_context():
        created = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )
        db_session.commit()

        resolved = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )

    assert resolved.id == created.id


def test_deactivated_user_is_refused(app, db_session):
    """A deactivated account is not resolved, so its access is not refreshed."""
    with app.app_context():
        user = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )
        user.active = False
        db_session.commit()

        with pytest.raises(Unauthorized):
            get_or_create_gen3_user_from_iss_sub(
                ISSUER, SUBJECT_ID, db_session=db_session
            )


def test_new_user_is_not_created_when_disallowed(app, db_session, monkeypatch):
    """
    With ALLOW_NEW_USER_ON_LOGIN off, an unseen visa identity does not get an account.

    The config comment for that setting promises the user can only log in once added
    to the Fence database by a separate process, which this path would otherwise
    sidestep entirely.
    """
    monkeypatch.setitem(config, "ALLOW_NEW_USER_ON_LOGIN", False)

    with app.app_context():
        with pytest.raises(Unauthorized):
            get_or_create_gen3_user_from_iss_sub(
                ISSUER, SUBJECT_ID, db_session=db_session
            )

        assert not query_for_user(session=db_session, username=USERNAME)


def test_existing_user_still_resolves_when_new_users_disallowed(
    app, db_session, monkeypatch
):
    """
    ALLOW_NEW_USER_ON_LOGIN gates creation only, not resolution.

    Guards against the new check being written so broadly that it locks out the
    pre-registered users such a deployment does expect to serve.
    """
    with app.app_context():
        created = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )
        db_session.commit()

        monkeypatch.setitem(config, "ALLOW_NEW_USER_ON_LOGIN", False)
        resolved = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )

    assert resolved.id == created.id


def test_cached_passport_resolves_active_user(
    app, db_session, cached_passport_for_user
):
    """A cache hit for an active user resolves that user without re-validation."""
    passport, _ = cached_passport_for_user

    with app.app_context():
        users = sync_gen3_users_authz_from_ga4gh_passports(
            [passport], db_session=db_session
        )

    assert list(users) == [USERNAME]


def test_cached_passport_does_not_resolve_deactivated_user(
    app, db_session, cached_passport_for_user
):
    """
    A cache hit does not resolve a user deactivated after their passport was cached.

    Otherwise deactivation would not take effect until the cache entry expired.
    """
    passport, user = cached_passport_for_user
    user.active = False
    db_session.commit()

    with app.app_context():
        users = sync_gen3_users_authz_from_ga4gh_passports(
            [passport], db_session=db_session
        )

    assert USERNAME not in users


@patch("httpx.get")
def test_deactivated_identity_blocks_sync_for_every_passport(
    mock_httpx_get, app, db_session, kid, rsa_private_key, monkeypatch
):
    """
    A passport for a deactivated user refuses the request before any access is synced.

    That includes an active user's passport submitted ahead of it in the same request,
    whose arborist access would otherwise be granted and left in place.
    """
    monkeypatch.setattr(passports_module, "PASSPORT_CACHE", {})
    db_session.query(GA4GHPassportCache).delete()
    db_session.commit()
    keys = [keypair.public_key_to_jwk() for keypair in app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    now = int(time.time())
    with app.app_context():
        deactivated = get_or_create_gen3_user_from_iss_sub(
            ISSUER, DEACTIVATED_SUBJECT_ID, db_session=db_session
        )
        deactivated.active = False
        db_session.commit()

        passports = [
            _encode_passport(SUBJECT_ID, rsa_private_key, kid, now),
            _encode_passport(DEACTIVATED_SUBJECT_ID, rsa_private_key, kid, now),
        ]
        with patch.object(
            passports_module, "_sync_validated_visa_authorization"
        ) as mock_sync:
            with pytest.raises(Unauthorized):
                sync_gen3_users_authz_from_ga4gh_passports(
                    passports, db_session=db_session
                )

    mock_sync.assert_not_called()
