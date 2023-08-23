import pytest
from cdislogging import get_logger

from fence import Oauth2ClientBase

MOCK_SETTINGS_ACR = {
    "client_id": "client",
    "client_secret": "hunter2",
    "redirect_url": "localhost",
    "multifactor_auth_claim_info": {
        "claim": "acr",
        "values": ["mfa", "otp", "duo", "sms", "phonecall"],
    },
}
MOCK_SETTINGS_AMR = {
    "client_id": "client",
    "client_secret": "hunter2",
    "redirect_url": "localhost",
    "multifactor_auth_claim_info": {
        "claim": "amr",
        "values": ["mfa", "otp", "duo", "sms", "phonecall"],
    },
}
logger = get_logger(__name__, log_level="debug")


@pytest.fixture()
def oauth_client_acr():
    return Oauth2ClientBase(settings=MOCK_SETTINGS_ACR, idp="mock", logger=logger)


@pytest.fixture()
def oauth_client_amr():
    return Oauth2ClientBase(settings=MOCK_SETTINGS_AMR, idp="mock", logger=logger)


def test_has_mfa_claim_acr(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "mfa"})
    assert has_mfa


def test_has_mfa_claim_acr(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "mfa"})
    assert has_mfa


def test_has_mfa_claim_multiple_acr(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "mfa otp duo"})
    assert has_mfa


def test_does_not_has_mfa_claim(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "pwd"})
    assert not has_mfa

    has_mfa = oauth_client_acr.has_mfa_claim({"something": "mfa"})
    assert not has_mfa


def test_does_not_has_mfa_claim_multiple(oauth_client_acr):
    has_mfa = oauth_client_acr.has_mfa_claim({"acr": "pwd trustme"})
    assert not has_mfa


def test_has_mfa_claim_amr(oauth_client_amr):
    has_mfa = oauth_client_amr.has_mfa_claim({"amr": ["mfa"]})
    assert has_mfa


def test_has_mfa_claim_multiple_amr(oauth_client_amr):
    has_mfa = oauth_client_amr.has_mfa_claim({"amr": ["mfa", "otp", "duo"]})
    assert has_mfa


def test_does_not_has_mfa_claim_amr(oauth_client_amr):
    has_mfa = oauth_client_amr.has_mfa_claim({"amr": ["pwd"]})
    assert not has_mfa

    has_mfa = oauth_client_amr.has_mfa_claim({"something": ["mfa"]})
    assert not has_mfa


def test_does_not_has_mfa_claim_multiple_amr(oauth_client_amr):
    has_mfa = oauth_client_amr.has_mfa_claim({"amr": ["pwd, trustme"]})
    assert not has_mfa
