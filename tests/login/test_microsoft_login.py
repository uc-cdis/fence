"""
Tests for fence.resources.openid.microsoft_oauth2.MicrosoftOauth2Client
"""
from unittest.mock import patch


def test_get_auth_url(microsoft_oauth2_client):
    """
    Test call to Get authorization uri from discovery doc
    """
    url = microsoft_oauth2_client.get_auth_url()

    assert url  # nosec


def test_get_user_id(microsoft_oauth2_client):
    """
    Test getting a user id and check for email claim
    """
    return_value = {"email": "user@contoso.com"}
    expected_value = {"email": "user@contoso.com"}
    with patch(
        "fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_jwt_claims_identity",
        return_value=return_value,
    ):
        user_id = microsoft_oauth2_client.get_user_id(code="123")
        assert user_id == expected_value  # nosec


def test_get_user_id_missing_claim(microsoft_oauth2_client):
    """
    Test getting a user id but missing the email claim
    """
    return_value = {"not_email_claim": "user@contoso.com"}
    expected_value = {"error": "Can't get user's Microsoft email!"}
    with patch(
        "fence.resources.openid.idp_oauth2.Oauth2ClientBase.get_jwt_claims_identity",
        return_value=return_value,
    ):
        user_id = microsoft_oauth2_client.get_user_id(code="123")
        assert user_id == expected_value  # nosec


def test_get_user_id_invalid_code(microsoft_oauth2_client):
    """
    Test getting a user id but with an invalid code
    """
    expected_value = "Can't get your Microsoft email:"

    user_id = microsoft_oauth2_client.get_user_id(code="123")
    assert expected_value in user_id["error"]  # nosec
