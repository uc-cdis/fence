import pytest
import random
import string
import jwt

from tests.utils import iat_and_exp

from fence.jwt.token import generate_signed_access_token, generate_signed_session_token
from fence.jwt.errors import JWTSizeError


def test_passport_access_token(app, kid, rsa_private_key, test_user_a):
    """
    Test that generate_signed_access_token is a valid GA4GH Passport Access Token
    as specified: https://github.com/ga4gh/data-security/blob/master/AAI/AAIConnectProfile.md#ga4gh-jwt-format

    The scopes argument is ["openid", "user", "ga4gh_passport_v1"] because there is currently no fixture for scopes in /tests/conftest.py,
    but default_claims() in /tests/utils/__init__.py sets aud = ["openid", "user"].
    """
    _, exp = iat_and_exp()
    jwt_token = generate_signed_access_token(
        kid,
        rsa_private_key,
        test_user_a,
        exp,
        ["openid", "user", "ga4gh_passport_v1"],
        client_id="client_a",
    )
    payload = jwt.decode(jwt_token.token, verify=False)
    # assert required fields exist
    assert payload["iss"] is not None or ""
    assert payload["sub"] is not None or ""
    assert payload["iat"] is not None
    assert payload["exp"] == payload["iat"] + exp
    assert payload["scope"] == ["openid", "user", "ga4gh_passport_v1"]
    assert isinstance(payload["aud"], list)
    # assert client_id in audiences
    assert "client_a" in payload["aud"]
