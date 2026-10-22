"""
DPOP_SHARED_SECRET is required only when fence runs as the web app (`app_config`), not on a
plain `config.load` (the path CLI/job processes such as fence-create take).
"""

import os

from flask import Flask
from mock import patch
import pytest
import yaml

import fence
from fence.config import DEFAULT_CFG_PATH, FenceConfig, config

TEST_CFG_PATH = os.path.join(os.path.dirname(__file__), "test-fence-config.yaml")
MISSING_SECRET_ERROR = (
    "DPOP_ENABLED is set but DPOP_SHARED_SECRET field empty or not set."
)


@pytest.fixture
def load_dpop_config(tmp_path, monkeypatch):
    """
    Return a function that loads the test config, with the given overrides, into a fresh
    `FenceConfig` the same way CLI processes do, leaving the `config` singleton untouched.
    """
    # `setenv` before `delenv` makes monkeypatch remove these at teardown, including the
    # DPOP_NONCE_TTL that `post_process` exports
    for name in ("DPOP_SHARED_SECRET", "DPOP_NONCE_TTL"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)

    def _load(**overrides):
        with open(TEST_CFG_PATH) as f:
            cfg = yaml.safe_load(f)
        cfg.update(overrides)
        path = tmp_path / "dpop-fence-config.yaml"
        path.write_text(yaml.safe_dump(cfg))
        return FenceConfig(DEFAULT_CFG_PATH).load(config_path=str(path))

    return _load


def test_plain_load_without_secret_does_not_raise(load_dpop_config):
    """CLI/job processes load the config with DPoP enabled and no secret."""
    cfg = load_dpop_config(DPOP_ENABLED=True, DPOP_SHARED_SECRET=None)
    assert cfg["DPOP_ENABLED"] is True
    assert not cfg["DPOP_SHARED_SECRET"]


def test_secret_env_var_overrides_config(load_dpop_config, monkeypatch):
    """The DPOP_SHARED_SECRET env var takes precedence over the config field."""
    monkeypatch.setenv("DPOP_SHARED_SECRET", "secret-from-env")
    cfg = load_dpop_config(DPOP_ENABLED=True, DPOP_SHARED_SECRET=None)
    assert cfg["DPOP_SHARED_SECRET"] == "secret-from-env"


@pytest.mark.parametrize("ttl", ["not-a-number", 0, -5])
def test_plain_load_rejects_bad_nonce_ttl(load_dpop_config, ttl):
    """A bad DPOP_NONCE_TTL still fails every process, not just the web app."""
    with pytest.raises(Exception, match="DPOP_NONCE_TTL"):
        load_dpop_config(DPOP_ENABLED=True, DPOP_NONCE_TTL=ttl)


def test_plain_load_exports_nonce_ttl(load_dpop_config):
    """DPOP_NONCE_TTL is parsed and exported for authutils to read."""
    cfg = load_dpop_config(DPOP_ENABLED=True, DPOP_NONCE_TTL="120")
    assert cfg["DPOP_NONCE_TTL"] == 120
    assert os.environ["DPOP_NONCE_TTL"] == "120"


def test_app_config_requires_secret(monkeypatch):
    """
    `app_config` (web app only) refuses to start when DPoP is enabled without a secret.
    `config.load` is patched out so the singleton keeps the values set here.
    """
    monkeypatch.setitem(config, "DPOP_ENABLED", True)
    monkeypatch.setitem(config, "DPOP_SHARED_SECRET", None)
    with patch.object(config, "load"):
        with pytest.raises(Exception, match=MISSING_SECRET_ERROR):
            fence.app_config(Flask("test_dpop_config"))


@pytest.mark.parametrize(
    "enabled,secret", [(True, "a-secret"), (False, None), (False, "a-secret")]
)
def test_validate_dpop_config_passes(monkeypatch, enabled, secret):
    """The web app check passes when a secret is set or DPoP is disabled."""
    monkeypatch.setitem(config, "DPOP_ENABLED", enabled)
    monkeypatch.setitem(config, "DPOP_SHARED_SECRET", secret)
    fence._validate_dpop_config()
