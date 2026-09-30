"""
Passport and visa validation resolves a signing key over the network from the token's
own ``iss`` claim, which could be attacker-controlled until the signature is checked. The
issuer allowlist must therefore be consulted before any key retrieval, or a submitted
token can steer outbound requests regardless of whether it is ultimately rejected.
"""

import time
from unittest.mock import patch

import jwt
import pytest

from fence.config import config
from fence.resources.ga4gh.passports import (
    get_unvalidated_visas_from_valid_passport,
    validate_visa,
)


EVIL_ISSUER = "https://evil.example.com/oidc"


def _encode_token(private_key, kid, claims):
    """Sign `claims` with the given key so the token is well formed but foreign."""
    return jwt.encode(claims, key=private_key, headers={"kid": kid}, algorithm="RS256")


@pytest.fixture
def evil_passport(rsa_private_key, kid):
    """A structurally valid passport whose issuer is not on the allowlist."""
    now = int(time.time())
    return _encode_token(
        rsa_private_key,
        kid,
        {
            "iss": EVIL_ISSUER,
            "sub": "attacker",
            "iat": now,
            "exp": now + 1000,
            "scope": "openid ga4gh_passport_v1",
            "ga4gh_passport_v1": [],
        },
    )


@pytest.fixture
def evil_visa(rsa_private_key, kid):
    """A structurally valid visa whose issuer is not on the allowlist."""
    now = int(time.time())
    return _encode_token(
        rsa_private_key,
        kid,
        {
            "iss": EVIL_ISSUER,
            "sub": "attacker",
            "iat": now,
            "exp": now + 1000,
            "scope": "openid ga4gh_passport_v1",
            "ga4gh_visa_v1": {
                "type": "https://ras.nih.gov/visas/v1.1",
                "asserted": now,
                "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
                "source": "https://ncbi.nlm.nih.gov/gap",
            },
        },
    )


def test_passport_with_foreign_issuer_yields_no_visas(app, evil_passport):
    """A passport from an issuer outside the allowlist contributes no visas."""
    with app.app_context():
        assert get_unvalidated_visas_from_valid_passport(evil_passport) == []


def test_passport_with_foreign_issuer_makes_no_outbound_request(app, evil_passport):
    """Rejecting a foreign-issuer passport does not fetch keys from its issuer."""
    with patch("httpx.get") as mock_get:
        with app.app_context():
            get_unvalidated_visas_from_valid_passport(evil_passport)

    assert not mock_get.called


def test_visa_with_foreign_issuer_is_rejected(app, evil_visa):
    """A visa from an issuer outside the allowlist is rejected."""
    with app.app_context():
        with pytest.raises(Exception):
            validate_visa(evil_visa)


def test_visa_with_foreign_issuer_makes_no_outbound_request(app, evil_visa):
    """Rejecting a foreign-issuer visa does not fetch keys from its issuer."""
    with patch("httpx.get") as mock_get:
        with app.app_context():
            with pytest.raises(Exception):
                validate_visa(evil_visa)

    assert not mock_get.called


def test_allowlisted_issuer_is_not_rejected_by_the_precheck(app, rsa_private_key, kid):
    """
    An allowlisted issuer still reaches signature validation.

    Guards against the issuer pre-check being written so strictly that it rejects the
    issuers the deployment actually trusts.
    """
    # A token issued by this application never triggers a key refresh, so the positive
    # control needs an allowlisted issuer other than BASE_URL to observe the fetch.
    allowed_issuer = next(
        issuer
        for issuer in config["GA4GH_VISA_ISSUER_ALLOWLIST"]
        if issuer != config["BASE_URL"]
    )
    now = int(time.time())
    passport = _encode_token(
        rsa_private_key,
        kid,
        {
            "iss": allowed_issuer,
            "sub": "someone",
            "iat": now,
            "exp": now + 1000,
            "scope": "openid ga4gh_passport_v1",
            "ga4gh_passport_v1": [],
        },
    )

    with patch("httpx.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"keys": []}
        with app.app_context():
            get_unvalidated_visas_from_valid_passport(passport)

    assert mock_get.called
