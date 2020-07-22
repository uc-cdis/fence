import pytest
import random
import string

from tests.utils import iat_and_exp

from fence.jwt.token import generate_signed_access_token, generate_signed_session_token
from fence.jwt.errors import JWTSizeError


def oversized_junk():
    """
    Return a string of random lowercase letters that is over 4096 bytes long.
    """
    return "".join(random.choice(string.ascii_lowercase) for _ in range(4097))


def test_oversized_access_token(app, rsa_private_key, test_user_a):
    """
    Test that generate_signed_access_token raises JTWSizeError  when the
    access token is over 4096 bytes.

    Here, the JWT is made to be large via the kid parameter in generate_signed_access_token.

    The scopes argument is ["openid", "user"] because there is currently no fixture for scopes in /tests/conftest.py,
    but default_claims() in /tests/utils/__init__.py sets aud = ["openid", "user"].
    """
    _, exp = iat_and_exp()
    with pytest.raises(JWTSizeError):
        generate_signed_access_token(
            oversized_junk(), rsa_private_key, test_user_a, exp, ["openid", "user"]
        )


def test_oversized_session_token(app, kid, rsa_private_key):
    """
    Test that generate_signed_session_token raises JWTSizeError when the
    session token is over 4096 bytes.
    Here, the JWT is made to be large via the context parameter in generate_signed_session_token.
    """
    _, exp = iat_and_exp()
    oversized_context = {"tmi": oversized_junk()}
    with pytest.raises(JWTSizeError):
        generate_signed_session_token(kid, rsa_private_key, exp, oversized_context)
