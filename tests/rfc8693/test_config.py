"""
Tests for the startup validation of the TOKEN_EXCHANGE configuration.
"""

import copy
from unittest.mock import patch

import pytest

from fence.config import FenceConfig
from tests.rfc8693.conftest import (
    TEST_ISSUER,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_GA4GH_PASSPORT,
    TOKEN_TYPE_JWT,
)

BASE_URL = "https://fence.example.com/user"
ACCESS_TOKEN_EXPIRES_IN = 1200

VALID_CONFIG = {
    "enabled": True,
    "allowed_subject_token_issuers": {
        TEST_ISSUER: {
            "allowed_subject_token_types": [TOKEN_TYPE_JWT, TOKEN_TYPE_GA4GH_PASSPORT],
            "allowed_requested_token_types": [TOKEN_TYPE_ACCESS_TOKEN],
            "allowed_scopes": ["openid", "user"],
        },
    },
}


def validate(
    token_exchange, visa_issuer_allowlist=(TEST_ISSUER,), passports_in_use=False
):
    FenceConfig._validate_token_exchange(
        token_exchange,
        list(visa_issuer_allowlist),
        BASE_URL,
        passports_in_use=passports_in_use,
        access_token_expires_in=ACCESS_TOKEN_EXPIRES_IN,
    )


@pytest.fixture(scope="function")
def token_exchange():
    """A valid TOKEN_EXCHANGE configuration, safe to modify."""
    return copy.deepcopy(VALID_CONFIG)


@pytest.fixture(scope="function")
def policy(token_exchange):
    """TEST_ISSUER's policy within ``token_exchange``, safe to modify."""
    return token_exchange["allowed_subject_token_issuers"][TEST_ISSUER]


def test_valid(token_exchange):
    validate(token_exchange)


def test_disabled_is_not_validated():
    validate(
        {
            "enabled": False,
            "allowed_subject_token_issuers": {BASE_URL: "not even a dict"},
        }
    )


def test_issuers_required(token_exchange):
    token_exchange["allowed_subject_token_issuers"] = {}
    with pytest.raises(Exception, match="allowed_subject_token_issuers is empty"):
        validate(token_exchange)


def test_subject_token_types_required(token_exchange, policy):
    del policy["allowed_subject_token_types"]
    with pytest.raises(Exception, match="no allowed_subject_token_types"):
        validate(token_exchange)


def test_issuer_policy_may_not_be_empty(token_exchange):
    """An issuer with no policy has no subject token types."""
    token_exchange["allowed_subject_token_issuers"][TEST_ISSUER] = None
    with pytest.raises(Exception, match="no allowed_subject_token_types"):
        validate(token_exchange)


def test_subject_token_type_must_have_a_handler(token_exchange, policy):
    policy["allowed_subject_token_types"].append(TOKEN_TYPE_ACCESS_TOKEN)
    with pytest.raises(Exception, match="cannot accept"):
        validate(token_exchange)


def test_requested_token_types_default(token_exchange, policy):
    del policy["allowed_requested_token_types"]
    validate(token_exchange)


def test_requested_token_types_not_empty(token_exchange, policy):
    policy["allowed_requested_token_types"] = []
    with pytest.raises(Exception, match="empty allowed_requested_token_types"):
        validate(token_exchange)


def test_requested_token_type_must_have_a_handler(token_exchange, policy):
    policy["allowed_requested_token_types"].append(
        "urn:ietf:params:oauth:token-type:refresh_token"
    )
    with pytest.raises(Exception, match="cannot issue"):
        validate(token_exchange)


def test_every_issuer_is_validated(token_exchange):
    token_exchange["allowed_subject_token_issuers"]["https://sts.nih.gov"] = {
        "allowed_subject_token_types": [TOKEN_TYPE_ACCESS_TOKEN],
    }
    with pytest.raises(Exception, match="'https://sts.nih.gov'"):
        validate(
            token_exchange, visa_issuer_allowlist=(TEST_ISSUER, "https://sts.nih.gov")
        )


def test_own_issuer_rejected(token_exchange):
    token_exchange["allowed_subject_token_issuers"][BASE_URL] = copy.deepcopy(
        VALID_CONFIG["allowed_subject_token_issuers"][TEST_ISSUER]
    )
    with pytest.raises(Exception, match="this Fence instance"):
        validate(token_exchange, visa_issuer_allowlist=(TEST_ISSUER, BASE_URL))


def test_issuer_policy_requires_openid(token_exchange, policy):
    policy["allowed_scopes"] = ["user"]
    with pytest.raises(Exception, match="'openid'"):
        validate(token_exchange)


def test_issuer_not_in_visa_allowlist_fails_when_passports_in_use(token_exchange):
    with pytest.raises(Exception, match="GA4GH_VISA_ISSUER_ALLOWLIST"):
        validate(token_exchange, visa_issuer_allowlist=(), passports_in_use=True)


def test_issuer_not_in_visa_allowlist_warns_otherwise(token_exchange):
    with patch("fence.config.logger.warning") as mock_warning:
        validate(token_exchange, visa_issuer_allowlist=(), passports_in_use=False)
    (message,), _ = mock_warning.call_args
    assert "GA4GH_VISA_ISSUER_ALLOWLIST" in message


def test_max_token_lifetime_above_default_warns(token_exchange, policy):
    """
    max_token_lifetime can only shorten an exchanged token, so a value above
    ACCESS_TOKEN_EXPIRES_IN has no effect.
    """
    policy["max_token_lifetime"] = ACCESS_TOKEN_EXPIRES_IN + 1
    with patch("fence.config.logger.warning") as mock_warning:
        validate(token_exchange)
    (message,), _ = mock_warning.call_args
    assert "max_token_lifetime" in message
    assert "ACCESS_TOKEN_EXPIRES_IN" in message


@pytest.mark.parametrize(
    "max_token_lifetime", [ACCESS_TOKEN_EXPIRES_IN, ACCESS_TOKEN_EXPIRES_IN - 1]
)
def test_max_token_lifetime_within_default_does_not_warn(
    token_exchange, policy, max_token_lifetime
):
    policy["max_token_lifetime"] = max_token_lifetime
    with patch("fence.config.logger.warning") as mock_warning:
        validate(token_exchange)
    mock_warning.assert_not_called()
