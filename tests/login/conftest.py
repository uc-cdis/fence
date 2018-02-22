import pytest

from tests import test_settings


@pytest.fixture(scope='function', autouse=True)
def patch_fence_settings(monkeypatch):
    """
    ``fence.blueprints.login`` loads in some variables from ``fence.settings``
    directly, so these need to be patched to their equivalents from the test
    settings.
    """
    monkeypatch.setattr('fence.settings', test_settings)
    monkeypatch.setattr(
        'fence.blueprints.login.default_idp',
        test_settings.ENABLED_IDENTITY_PROVIDERS['default']
    )
    monkeypatch.setattr(
        'fence.blueprints.login.idps',
        test_settings.ENABLED_IDENTITY_PROVIDERS['providers']
    )
