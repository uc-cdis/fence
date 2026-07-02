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
        exp,
        ["openid", "user", "ga4gh_passport_v1"],
        user=test_user_a,
        client_id="client_a",
    )
    payload = jwt.decode(
        jwt_token.token, options={"verify_signature": False}, algorithms=["RS256"]
    )
    # assert required fields exist
    assert payload["iss"] is not None or ""
    assert payload["sub"] is not None or ""
    assert payload["iat"] is not None
    assert payload["exp"] == payload["iat"] + exp
    assert payload["scope"] == ["openid", "user", "ga4gh_passport_v1"]
    assert isinstance(payload["aud"], list)
    # assert client_id in audiences
    assert "client_a" in payload["aud"]


def test_task_token_access_token(app, kid, rsa_private_key, test_user_a):
    """
    Test that generate_signed_access_token has a context field with
    task_token_type when task_token_type is provided and no field when task_token_type is not provided.
    """
    _, exp = iat_and_exp()
    jwt_token = generate_signed_access_token(
        kid,
        rsa_private_key,
        exp,
        ["openid", "user"],
        user=test_user_a,
        task_token_type="test_task_token",
    )
    payload = jwt.decode(
        jwt_token.token, options={"verify_signature": False}, algorithms=["RS256"]
    )

    # assert task_token_type in context
    assert "context" in payload
    assert "task_token_type" in payload["context"]
    assert (
        payload["context"]["task_token_type"] == "test_task_token"
    ), f"Expected task_token_type 'test_task_token', but got {payload['context']['task_token_type']}"

    jwt_token = generate_signed_access_token(
        kid,
        rsa_private_key,
        exp,
        ["openid", "user"],
        user=test_user_a,
        task_token_type=None,
    )
    payload = jwt.decode(
        jwt_token.token, options={"verify_signature": False}, algorithms=["RS256"]
    )
    # assert task_token_type is not in context
    assert "context" in payload
    assert (
        "task_token_type" not in payload["context"]
    ), f"Expected task_token_type not to be present, but got {payload['context']['task_token_type']}"
