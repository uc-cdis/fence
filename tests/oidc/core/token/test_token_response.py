"""
Test just the actual return value from the token endpoint.
"""

import pytest

from fence.jwt.validate import validate_jwt

from tests.utils import oauth2


@pytest.fixture(scope='function')
def token_response_json(client, oauth_client):
    """
    Define a fixture for this module for a successful token response.
    """
    return oauth2.get_token_response(client, oauth_client).json


def test_token_response(token_response_json):
    """
    Test that response from the token endpoint contains the expected fields.
    """
    # Check the fields in the response.
    assert 'id_token' in token_response_json
    assert 'access_token' in token_response_json
    assert 'refresh_token' in token_response_json
    assert 'token_type' in token_response_json
    assert 'expires_in' in token_response_json


def test_token_type(token_response_json):
    """
    Test that the value of ``token_type`` in the response is ``'Bearer'``.
    """
    assert 'token_type' in token_response_json
    # Check the token type value.
    assert token_response_json['token_type'] == 'Bearer'


def test_id_token_required_fields(token_response_json):
    """
    Test that the ID token returned in the token response is a valid JWT, and
    that it contains all of fields required by OIDC.
    """
    assert 'id_token' in token_response_json
    # Check that the ID token is a valid JWT.
    id_token = validate_jwt(token_response_json['id_token'], 'openid')
    # Check for required fields.
    assert 'iss' in id_token
    assert 'sub' in id_token
    assert 'aud' in id_token
    assert 'exp' in id_token
    assert 'iat' in id_token
    # Check for types on required fields.
    assert type(id_token['exp']) is int
    assert type(id_token['iat']) is int
