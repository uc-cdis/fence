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


@pytest.fixture(autouse=True, scope="function")
def mock_file_contents(monkeypatch, privacy_policy_md, privacy_policy_html):
    monkeypatch.setattr(
        fence.blueprints.privacy, "PRIVACY_POLICY_MD", privacy_policy_md
    )
    monkeypatch.setattr(
        fence.blueprints.privacy, "PRIVACY_POLICY_HTML", privacy_policy_html
    )
