"""
Test just the actual return value from the token endpoint.
"""

from fence.jwt.validate import validate_jwt


def test_token_response(token_response):
    """
    Test that response from the token endpoint contains the expected fields.
    """
    # Check the fields in the response.
    assert "id_token" in token_response.json
    assert "access_token" in token_response.json
    assert "refresh_token" in token_response.json
    assert "token_type" in token_response.json
    assert "expires_in" in token_response.json


def test_token_type(token_response):
    """
    Test that the value of ``token_type`` in the response is ``Bearer``.
    """
    # Check the token type value (it must be ``Bearer``).
    assert "token_type" in token_response.json
    assert token_response.json["token_type"] == "Bearer"
    # Check specific header values.
    assert "Cache-Control" in token_response.headers
    assert token_response.headers["Cache-Control"] == "no-store"
    assert "Pragma" in token_response.headers
    assert token_response.headers["Pragma"] == "no-cache"


def test_id_token_required_fields(token_response):
    """
    Test that the ID token returned in the token response is a valid JWT, and
    that it contains all of fields required by OIDC.
    """
    assert "id_token" in token_response.json
    # Check that the ID token is a valid JWT.
    id_token = validate_jwt(token_response.json["id_token"], {"openid"})
    # Check for required fields.
    assert "pur" in id_token and id_token["pur"] == "id"

    assert "iss" in id_token
    assert "sub" in id_token
    assert "aud" in id_token
    assert "exp" in id_token
    assert "iat" in id_token
    # Check for types on required fields.
    assert type(id_token["exp"]) is int
    assert type(id_token["iat"]) is int

    assert type(id_token["sub"]) is str
    assert type(id_token["iss"]) is str
    assert type(id_token["aud"]) is list


def test_access_token_correct_fields(token_response):
    """
    Test that the access token from the token response contains exactly the
    expected fields.
    """
    encoded_access_token = token_response.json["access_token"]
    access_token = validate_jwt(encoded_access_token, {"openid"})
    access_token_fields = set(access_token.keys())
    expected_fields = {
        "pur",
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "jti",
        "scope",
        "context",
        "azp",
    }
    assert access_token_fields == expected_fields
