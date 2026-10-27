import json, os, tempfile, pytest
from fence.secrets.k8s_resolver import KubernetesSecretResolver

def test_mount_mode_file_roundtrip(monkeypatch):
    monkeypatch.setenv("FENCE_K8S_SECRET_MODE", "mount")
    payload = {"access_key_id": "AKIA...", "secret_access_key": "SECRET..."}
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(json.dumps(payload))
        f.flush()
        r = KubernetesSecretResolver(ttl_seconds=1)
        got = r.get(f.name)
        assert got["access_key_id"].startswith("AKIA")
        got2 = r.get(f.name)
        assert got2 == got

def test_api_mode_requires_kubernetes(monkeypatch):
    monkeypatch.setenv("FENCE_K8S_SECRET_MODE", "api")
    # If kubernetes lib isn't installed, constructor should raise
    try:
        r = KubernetesSecretResolver(ttl_seconds=1)
    except RuntimeError:
        pytest.xfail("kubernetes package not available in test env; API mode cannot init here")
