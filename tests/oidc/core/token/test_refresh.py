"""
Test specifically the behavior of using a refresh token at the token endpoint.

OIDC spec for successful refresh response:

    If an ID Token is returned as a result of a token refresh request, the
    following requirements apply:
    - its iss Claim Value MUST be the same as in the ID Token issued when the
      original authentication occurred,
    - its sub Claim Value MUST be the same as in the ID Token issued when the
      original authentication occurred,
    - its iat Claim MUST represent the time that the new ID Token is issued,
    - its aud Claim Value MUST be the same as in the ID Token issued when the
      original authentication occurred,
    - if the ID Token contains an auth_time Claim, its value MUST represent the
      time of the original authentication - not the time that the new ID token
      is issued,
    - its azp Claim Value MUST be the same as in the ID Token issued when the
      original authentication occurred; if no azp Claim was present in the
      original ID Token, one MUST NOT be present in the new ID Token, and
    - otherwise, the same rules apply as apply when issuing an ID Token at the
      time of the original authentication.
"""

from fence.jwt.validate import validate_jwt


def test_same_claims(oauth_test_client, token_response_json):
    original_id_token = token_response_json["id_token"]
    original_claims = validate_jwt(original_id_token, {"openid"})
    refresh_token = token_response_json["refresh_token"]
    refresh_token_response = oauth_test_client.refresh(
        refresh_token=refresh_token
    ).response
    assert "id_token" in refresh_token_response.json
    new_claims = validate_jwt(refresh_token_response.json["id_token"], {"openid"})
    assert original_claims["iss"] == new_claims["iss"]
    assert original_claims["sub"] == new_claims["sub"]
    assert original_claims["iat"] <= new_claims["iat"]
    assert original_claims["aud"] == new_claims["aud"]
    if "azp" in original_claims:
        assert original_claims["azp"] == new_claims["azp"]
    else:
        assert "azp" not in new_claims
