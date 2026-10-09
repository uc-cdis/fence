"""
Passport and visa validation resolves a signing key over the network from the token's
own ``iss`` claim, which is untrusted until the signature is checked. The issuer
allowlist must therefore be consulted before any key retrieval, or a submitted token can
steer outbound requests regardless of whether it is ultimately rejected.
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


UNLISTED_ISSUER = "https://unlisted-issuer.example.com/oidc"


def _encode_token(private_key, kid, claims):
    """Sign `claims` with the given key so the token is well formed but unlisted."""
    return jwt.encode(claims, key=private_key, headers={"kid": kid}, algorithm="RS256")


@pytest.fixture
def unlisted_passport(rsa_private_key, kid):
    """A structurally valid passport whose issuer is not on the allowlist."""
    now = int(time.time())
    return _encode_token(
        rsa_private_key,
        kid,
        {
            "iss": UNLISTED_ISSUER,
            "sub": "unlisted-user",
            "iat": now,
            "exp": now + 1000,
            "scope": "openid ga4gh_passport_v1",
            "ga4gh_passport_v1": [],
        },
    )


@pytest.fixture
def unlisted_visa(rsa_private_key, kid):
    """A structurally valid visa whose issuer is not on the allowlist."""
    now = int(time.time())
    return _encode_token(
        rsa_private_key,
        kid,
        {
            "iss": UNLISTED_ISSUER,
            "sub": "unlisted-user",
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


def test_passport_with_unlisted_issuer_yields_no_visas(app, unlisted_passport):
    """A passport from an issuer outside the allowlist contributes no visas."""
    with app.app_context():
        assert get_unvalidated_visas_from_valid_passport(unlisted_passport) == []


def test_passport_with_unlisted_issuer_makes_no_outbound_request(
    app, unlisted_passport
):
    """Rejecting an unlisted-issuer passport does not fetch keys from its issuer."""
    with patch("httpx.get") as mock_get:
        with app.app_context():
            get_unvalidated_visas_from_valid_passport(unlisted_passport)

    assert not mock_get.called


def test_visa_with_unlisted_issuer_is_rejected(app, unlisted_visa):
    """A visa from an issuer outside the allowlist is rejected."""
    with app.app_context():
        with pytest.raises(Exception):
            validate_visa(unlisted_visa)


def test_visa_with_unlisted_issuer_makes_no_outbound_request(app, unlisted_visa):
    """Rejecting an unlisted-issuer visa does not fetch keys from its issuer."""
    with patch("httpx.get") as mock_get:
        with app.app_context():
            with pytest.raises(Exception):
                validate_visa(unlisted_visa)

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
