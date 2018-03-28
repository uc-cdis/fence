"""
Define Keypair object for holding key id to keypair mapping, and functions to
get default public and private keys for the fence app. The app must be
configured with the attribute ``app.keypairs``.

Attributes:
    Keypair: object for storing key id to keypair associations
    default_public_key (Callable[[flask.Flask], str]):
        return default public key for the app
    default_private_key (Callable[[flask.Flask], str]):
        return default private key for the app
"""

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import flask
from jose import jwk


class Keypair(object):
    """
    Define a store for a public and private keypair associated with a key id
    ``kid``.

    Args:
        kid (str): the key id
        public (str): the public key
        private (str): the private key
    """

    def __init__(self, kid, public_key, private_key):
        self.kid = kid
        self.public_key = public_key
        self.private_key = private_key

    def public_key_to_jwk(self):
        """
        Get the JWK representation of the public key in this keypair according
        to the specification of RFC 7517.

        Fence only uses RSA, and the public keys are only used for JWT
        validation, so it is assumed both all keys should have type ``RSA``
        (and therefore contain fields ``n`` and ``e`` for the public key
        modulus and exponent), and the values of ``use`` and ``key_ops`` are
        also hard-coded accordingly.

        Return:
            dict: JWK representation of the public key
        """
        n, e = _rsa_public_numbers(self.public_key)
        jwk_dict = jwk.construct(self.public_key, algorithm='RS256').to_dict()
        jwk_dict.update({
            'use': 'sig',
            'key_ops': 'verify',
            'kid': self.kid,
        })
        return jwk_dict


def _rsa_public_numbers(public_key_data):
    """
    Take the data for a public key (string of the key in PEM format) and return
    the public key modulus ``n`` and exponent ``e`` for that key.

    The values of n and e are needed for the return of the JWKS endpoint.

    Args:
        public_key_data (str): the public key

    Return:
        Tuple[int, int]: the public key modulus ``n`` and exponent ``e``
    """
    key = serialization.load_pem_public_key(public_key_data, default_backend())
    numbers = key.public_numbers()
    return (numbers.n, numbers.e)


def default_public_key(app=flask.current_app):
    """
    Return the default (first) public key for the given app.
    """
    return app.keypairs[0].public_key


def default_private_key(app=flask.current_app):
    """
    Return the default (first) private key for the given app.
    """
    return app.keypairs[0].private_key
