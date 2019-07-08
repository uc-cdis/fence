"""
NOTE: the tests use ``pytest.mark.filterwarnings('ignore')`` because SQLAlchemy
isn't happy if you try to load a table a second time, which we have to
inadvertently do when we reload all the fence submodules.
"""

import importlib
import sys

import pytest
from sqlalchemy.exc import InvalidRequestError


def reload_modules(module_name):
    """
    Reload all of fence's submodules.

    Use this after patching ``local_settings.py`` not existing, to make sure
    that nothing will remember that it existed.
    """
    # First we have to convince fence that ``local_settings.py`` does not
    # actually exist, even if it does. To do this, patch-delete the attribute
    # and reload all the fence modules.
    fence_submodules = [
        module for module in list(sys.modules.keys()) if module.startswith(module_name)
    ]
    for module in fence_submodules:
        if sys.modules[module]:
            # SQLAlchemy gets upset when a table is loaded twice, so ignore
            # that.
            try:
                importlib.reload(sys.modules[module])
            except InvalidRequestError:
                pass


class FakeModule(object):
    """
    Define a context manager for instantiating a fake copy of a module under an
    arbitrary module name.

    We use this to make a copy of fence from which the local settings module is
    removed, without disturbing the normal fence.
    """

    def __init__(self, real_name, fake_name):
        """Save a copy of the real module."""
        self.real_name = real_name
        self.fake_name = fake_name
        # Save a copy of the real module.
        importlib.import_module(self.real_name)
        self.real_module = sys.modules.pop(self.real_name)

    def __enter__(self):
        """
        Insert a copy of the real module into ``sys.modules`` under the fake
        name.
        """
        sys.modules[self.fake_name] = importlib.import_module(self.real_name)

    def __exit__(self, type, value, traceback):
        """
        Remove the fake module and put the real module back in ``sys.modules``.

        (The arguments are required for a context manager.)
        """
        sys.modules.pop(self.fake_name)
        sys.modules[self.real_name] = self.real_module


@pytest.mark.filterwarnings("ignore")
def test_import_without_local_settings(app, monkeypatch):
    """
    Simply try to import fence when ``fence.local_settings`` doesn't exist.
    """
    with FakeModule("fence", "test_fence"):
        # Take out the local settings module and reload ``test_fence``.
        monkeypatch.delattr("test_fence.local_settings", raising=False)
        reload_modules("test_fence")
        # Now try to import fence.
        import test_fence

        assert hasattr(test_fence, "app")


@pytest.mark.filterwarnings("ignore")
def test_import_fence_would_break(monkeypatch):
    """
    Sort of test the previous test by making sure that if ``local_settings.py``
    did not exist and we tried to use it, things would go horribly wrong.
    """
    with FakeModule("fence", "test_fence"):
        # Take out the local settings module and reload ``test_fence``.
        monkeypatch.delattr("test_fence.local_settings", raising=False)
        reload_modules("test_fence")
        # Import ``test_fence`` and make sure that using the local settings
        # would break things.
        import test_fence

        assert not hasattr(test_fence, "local_settings")
        # Try to get an arbitrary variable from ``local_settings`` and make
        # sure it fails.
        with pytest.raises(AttributeError):
            test_fence.local_settings.DB
