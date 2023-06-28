import pytest
from cdislogging import get_logger

from fence import Oauth2ClientBase

MOCK_SETTINGS = {
    "client_id": "client",
    "client_secret": "hunter2",
    "redirect_url": "localhost",
    "multifactor_auth_claim_info": {
        "claim": "acr",
        "values": ["mfa", "otp", "duo", "sms", "phonecall"],
    },
}
logger = get_logger(__name__, log_level="debug")


@pytest.fixture()
def oauth_client():
    return Oauth2ClientBase(settings=MOCK_SETTINGS, idp="mock", logger=logger)


def test_has_mfa_claim(oauth_client):
    has_mfa = oauth_client.has_mfa_claim({"acr": "mfa"})
    assert has_mfa


def test_has_mfa_claim_multiple_acr(oauth_client):
    has_mfa = oauth_client.has_mfa_claim({"acr": "mfa otp duo"})
    assert has_mfa


def test_does_not_has_mfa_claim(oauth_client):
    has_mfa = oauth_client.has_mfa_claim({"acr": "pwd"})
    assert not has_mfa


def test_does_not_has_mfa_claim_multiple(oauth_client):
    has_mfa = oauth_client.has_mfa_claim({"acr": "pwd trustme"})
    assert not has_mfa
