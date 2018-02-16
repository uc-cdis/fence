"""
Do a couple basic tests to check that the default keys are returned correctly.
"""

from fence import keys


def test_default_public_key(app, public_key):
    """Test that the default public key is correct."""
    assert keys.default_public_key() == public_key


def test_default_private_key(app, private_key):
    """Test that the default private key is correct."""
    assert keys.default_private_key() == private_key
