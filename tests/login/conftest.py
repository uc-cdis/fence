import pytest

from tests import test_settings


@pytest.fixture(scope='function', autouse=True)
def patch_fence_settings(monkeypatch):
    monkeypatch.setattr('fence.settings', test_settings)
    monkeypatch.setattr(
        'fence.blueprints.login.default_idp',
        test_settings.IDENTITY_PROVIDERS['default']
    )
    monkeypatch.setattr(
        'fence.blueprints.login.idps',
        test_settings.IDENTITY_PROVIDERS['providers']
    )
