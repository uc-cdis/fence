import os

from markdown import Markdown
import pytest

import fence.blueprints.privacy


@pytest.fixture(scope="session")
def privacy_policy_md():
    return "# Gen3/DCFS Privacy Policy"


@pytest.fixture(scope="session")
def privacy_policy_html():
    return "<h1>Gen3/DCFS Privacy Policy</h1>"


@pytest.fixture(scope="function", autouse=True)
def mock_get_data(monkeypatch, privacy_policy_md):
    monkeypatch.setattr(
        fence.blueprints.privacy.pkgutil,
        "get_data",
        lambda *args, **kwargs: bytes(privacy_policy_md, "utf-8"),
    )
