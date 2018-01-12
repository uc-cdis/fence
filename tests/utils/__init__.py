import os
import tests
from datetime import datetime, timedelta
import uuid

import tests.utils.oauth2


def read_file(filename):
    """Read the contents of a file in the tests directory."""
    root_dir = os.path.dirname(os.path.realpath(tests.__file__))
    with open(os.path.join(root_dir, filename), 'r') as f:
        return f.read()


def new_jti():
    """
    Return a fresh jti (JWT token ID).
    """
    return str(uuid.uuid4())


def iat_and_exp():
    """
    Return ``iat`` and ``exp`` claims for a JWT.
    """
    now = datetime.now()
    iat = int(now.strftime('%s'))
    exp = int((now + timedelta(seconds=60)).strftime('%s'))
    return (iat, exp)


def default_claims():
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['access', 'user']
    iss = 'https://user-api.test.net'
    jti = new_jti()
    iat, exp = iat_and_exp()
    azp = ''
    return {
        'aud': aud,
        'sub': '1234',
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'azp': azp,
        'context': {
            'user': {
                'name': 'test-user',
                'projects': [
                ],
            },
        },
    }


def unauthorized_context_claims():
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['access', 'user']
    iss = 'https://user-api.test.net'
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'aud': aud,
        'sub': '1234',
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': 'test-user',
                'projects': {
                    "phs000178": ["read"],
                    "phs000234": ["read", "read-storage"],
                },
            },
        },
    }


def authorized_context_claims():
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['access', 'user']
    iss = 'https://user-api.test.net'
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'aud': aud,
        'sub': '1234',
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': 'test-user',
                'projects': {
                    "phs000178": ["read"],
                    "phs000218": ["read", "read-storage"],
                },
            },
        },
    }
