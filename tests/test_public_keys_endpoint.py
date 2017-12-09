from collections import OrderedDict
import os

from .test_settings import JWT_KEYPAIR_FILES


def read_file(filename):
    """Read the contents of a file in the current directory."""
    root_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(root_dir, filename), 'r') as f:
        return f.read()


def test_keys_endpoint(app, client):
    """
    Test the return value from the ``/jwt/keys`` endpoint against the
    configuration for the app.
    """
    response = client.get('/jwt/keys')
    assert 'keys' in response.json, response.data
    public_keys = response.json.get('keys')
    assert public_keys, response.json

    comparison = zip(public_keys, JWT_KEYPAIR_FILES.items())
    for (kid, public_key), (settings_kid, (public_key_file, _)) in comparison:
        assert kid == settings_kid
        assert public_key == read_file(public_key_file)


def test_reconstruct_keys_dict(app, client):
    """
    Test that reconstructing the dictionary mapping key ids to public keys from
    the return value from the public keys endpoint.
    """
    response = client.get('/jwt/keys')
    public_keys_dict = OrderedDict(response.json['keys'])
    assert public_keys_dict == app.jwt_public_keys
