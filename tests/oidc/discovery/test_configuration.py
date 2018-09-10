"""
Test the ``/.well-known/openid-configuration`` endpoint.
"""

import warnings


def test_oidc_config_fields(app, client):
    """
    Test that the configuration response at least contains the required fields.
    For fields which are recommended but not required, issue a warning.
    """
    response = client.get("/.well-known/openid-configuration")
    assert response.status_code == 200, response.data

    # Check for required fields.
    required_fields = [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ]
    for field in required_fields:
        assert field in response.json

    # For recommended fields, warn if not contained in the response.
    recommended_fields = [
        "userinfo_endpoint",
        "registration_endpoint",
        "scopes_supported",
        "claims_supported",
    ]

    for field in recommended_fields:
        if field not in response.json:
            warnings.warn(
                "OIDC configuration response missing recommended field: " + field
            )
