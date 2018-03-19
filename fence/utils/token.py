import time
import uuid


def new_jti():
    """
    Return a fresh jti (JWT token ID).
    """
    return str(uuid.uuid4())


def iat_and_exp():
    """
    Return ``iat`` and ``exp`` claims for a JWT.
    """
    iat = int(time.time())
    exp = iat + 600
    return (iat, exp)


def default_claims():
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['openid', 'user']
    iss = 'https://user-api.test.net'
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'pur': 'access',
        'aud': aud,
        'sub': '1234',
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': 'test-user',
                'projects': [
                ],
            },
        },
    }


def generate_example_token_claims(override=None):
    """
    Generate an example dictionary of token claims for a JWT.

    Args:
        override (dict): dictionary of fields to override in result claims

    Return:
        dict: claims for a JWT
    """
    override = override or {}
    claims = default_claims()
    claims.update(override)
