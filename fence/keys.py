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

import flask


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


def default_public_key(app=flask.current_app):
    """
    Return the default (first) public key for the given app.
    """
    return app.keypairs.values()[0].public_key


def default_private_key(app=flask.current_app):
    """
    Return the default (first) private key for the given app.
    """
    return app.keypairs.values()[0].private_key
