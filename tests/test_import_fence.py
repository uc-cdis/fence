"""
NOTE: the tests use ``pytest.mark.filterwarnings('ignore')`` because SQLAlchemy
isn't happy if you try to load a table a second time, which we have to
inadvertently do when we reload all the fence submodules.
"""

import sys

import pytest
from sqlalchemy.exc import InvalidRequestError


def reload_fence_modules():
    """
    Reload all of fence's submodules.

    Use this after patching ``local_settings.py`` not existing, to make sure
    that nothing will remember that it existed.
    """
    # First we have to convince fence that ``local_settings.py`` does not
    # actually exist, even if it does. To do this, patch-delete the attribute
    # and reload all the fence modules.
    fence_submodules = [
        module for module in sys.modules.keys() if module.startswith('fence')
    ]
    for module in fence_submodules:
        if sys.modules[module]:
            # SQLAlchemy gets upset when a table is loaded twice, so ignore
            # that.
            try:
                # NOTE: in python3 this should become ``importlib.reload``
                reload(sys.modules[module])
            except InvalidRequestError:
                pass


@pytest.mark.filterwarnings('ignore')
def test_import_without_local_settings(monkeypatch):
    """
    Simply try to import fence when ``fence.local_settings`` doesn't exist.
    """
    monkeypatch.delattr('fence.local_settings', raising=False)
    reload_fence_modules()
    # Now try to import fence.
    import fence
    assert hasattr(fence, 'app')


@pytest.mark.filterwarnings('ignore')
def test_import_fence_would_break(monkeypatch):
    """
    Sort of test the previous test by making sure that if ``local_settings.py``
    did not exist and we tried to use it, things would go horribly wrong.
    """
    monkeypatch.delattr('fence.local_settings', raising=False)
    reload_fence_modules()
    import fence
    assert not hasattr(fence, 'local_settings')
    # Try to get an arbitrary variable from ``local_settings`` and make sure it
    # fails.
    with pytest.raises(AttributeError):
        fence.local_settings.DB
