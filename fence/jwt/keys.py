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

import datetime
import os

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import dateutil.parser
import flask
from jose import jwk


def load_keypairs(keys_dir):
    """
    Load a list of all the available keypairs from the given directory. (The
    given directory should be ``fence/keys``.

    Args:
        keys_dir (str):
            the directory in which keypair subdirectories are kept; generally
            should just be the absolute path to ``fence/keys``

    Return:
        List[Keypair]:
            the keypairs loaded from the directory, sorted in order of most
            recent date according to either name (if the directory is named in
            ISO date format) or time last modified, if the name is not
            formatted in ISO
    """
    if not os.path.isdir(keys_dir):
        raise EnvironmentError(
            "Keypair directory not found. Make sure `{}` directory exists. "
            "Inside that directory should be another folder containing "
            "key files `jwt_public_key.pem` and `jwt_private_key.pem`.".format(keys_dir)
        )

    # Get the absolute paths for the keypair directories.
    keypair_directories = [os.path.join(keys_dir, d) for d in os.listdir(keys_dir)]

    def is_datetime(name):
        try:
            dateutil.parser.parse(os.path.basename(name))
            return True
        except ValueError:
            return False

    def timestamp_key(name):
        return dateutil.parser.parse(os.path.basename(name))

    directories_timestamped = list(
        reversed(
            sorted(
                (d for d in keypair_directories if is_datetime(d)), key=timestamp_key
            )
        )
    )
    directories_other = list(
        sorted(d for d in keypair_directories if not is_datetime(d))
    )

    # Sort the keypair directories to load from in the order described in
    # ``key``.
    keypair_directories = directories_timestamped + directories_other

    # Load the keypairs from the directories.
    keypairs = [
        Keypair.from_directory(d) for d in keypair_directories if os.path.isdir(d)
    ]

    if not keypairs:
        raise EnvironmentError(
            "Keypairs not found. Make sure `{}` directory exists. "
            "Inside that directory should be another folder containing "
            "key files `jwt_public_key.pem` and `jwt_private_key.pem`.".format(keys_dir)
        )

    return keypairs


class Keypair(object):
    """
    Define a store for a public and private keypair associated with a key id
    ``kid``.

    Args:
        kid (str): the key id
        public (str): the public key
        private (str): the private key

    Raises:
        ValueError:
            as a precaution, if the private key does not say "PRIVATE KEY", or
            if the public key does say "PRIVATE KEY"
    """

    def __init__(self, kid, public_key, private_key):
        # Raise an error if either key does not match our expectations that the
        # private key should be private and the public key should not be
        # private.
        if "PRIVATE KEY" not in str(private_key):
            raise ValueError("received private key that was not an RSA private key")
        if "PRIVATE KEY" in str(public_key):
            raise ValueError("received public key that was actually an RSA private key")

        self.kid = kid
        self.public_key = public_key
        self.private_key = private_key

    @classmethod
    def from_directory(cls, keys_dir, naming_function=None):
        """
        Load a keypair from the given directory. The directory must contain the
        files ``jwt_public_key.pem`` and ``jwt_private_key.pem``, or this
        function will raise an ``EnvironmentError``.

        Args:
            cls (Keypair): should be just the keypair class
            keys_dir (str): directory to load the keys from
            naming_function (Optional[Callable[[str], str]]):
                function to call on the keys directory to generate the key id
                (``kid``) used for the returned keypair; the default will, for
                example if the keys are stored in the directory
                ``2018-05-01T14:00:00Z``, assign the key ID as
                ``fence_key_2018-05-01T14:00:00Z``.

        Return:
            Keypair: the keypair instance loaded from the directory

        Raises:
            EnvironmentError: if the public or private key files are missing
        """
        if naming_function is None:
            naming_function = lambda d: "fence_key_" + d

        pub_filepath = os.path.join(keys_dir, "jwt_public_key.pem")
        prv_filepath = os.path.join(keys_dir, "jwt_private_key.pem")

        if not os.path.isfile(pub_filepath):
            # Generate public key from private key
            with open(prv_filepath, "r") as f:
                private_key_file = f.read()
                private_key = serialization.load_pem_private_key(
                    bytes(private_key_file, "utf-8"),
                    password=None,
                    backend=default_backend(),
                )
                public_key = private_key.public_key()
                public_key = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                public_key = public_key.decode("utf-8")
                with open(pub_filepath, "w") as f:
                    f.write(public_key)

        if not os.path.isfile(prv_filepath):
            raise EnvironmentError(
                "missing private key file; expected file to exist: " + prv_filepath
            )

        with open(pub_filepath, "r") as f:
            public_key = f.read()

        with open(prv_filepath, "r") as f:
            private_key = f.read()

        kid = naming_function(os.path.basename(keys_dir))

        return cls(kid, public_key, private_key)

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
        jwk_dict = jwk.construct(self.public_key, algorithm="RS256").to_dict()
        for k in jwk_dict:  # convert byte values to string
            try:
                jwk_dict[k] = jwk_dict[k].decode("utf-8")
            except AttributeError:
                # there is no need to decode values that are already strings
                pass
        jwk_dict.update({"use": "sig", "key_ops": ["verify"], "kid": self.kid})
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
    key = serialization.load_pem_public_key(
        bytes(public_key_data, "utf-8"), default_backend()
    )
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
