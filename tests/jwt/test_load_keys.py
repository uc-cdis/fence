"""
Test that the logic for loading keypairs onto the app is working correctly.

For details, see ``load_keypairs`` in ``fence.jwt.keys`` and other
documentation in that file.
"""

import flask
import pytest

from fence import app_init

from tests import test_settings


@pytest.fixture
def test_keys_app(root_dir):
    """
    A Flask application used to test the keypair loading procedure.
    """
    app = flask.Flask('test_load_keys_app')
    app_init(app, test_settings, root_dir=root_dir)
    return app


def test_load_keys(test_keys_app):
    """
    Test that fence loads the keypairs as expected.
    """
    kids = [keypair.kid for keypair in test_keys_app.keypairs]
    # NOTE: hardcoded from files in ``fence/tests/keys/``.
    expected = [
        'fence_key_2018-06-11T16:01:39Z',
        'fence_key_2018-05-01T21:29:02Z',
    ]
    assert kids == expected
