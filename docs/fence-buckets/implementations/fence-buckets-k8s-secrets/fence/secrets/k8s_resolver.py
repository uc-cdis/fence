from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Mapping, Optional, Dict

from time import monotonic

try:
    from kubernetes import client, config  # type: ignore
except Exception:  # pragma: no cover
    client = None
    config = None


@dataclass
class _CacheEntry:
    val: Dict[str, str]
    exp: float


class TimedCache:
    def __init__(self, ttl_seconds: int = 600, max_entries: int = 256):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._data: Dict[str, _CacheEntry] = {}

    def get(self, key: str, loader):
        now = monotonic()
        ent = self._data.get(key)
        if ent and now < ent.exp:
            return ent.val
        val = loader()
        if len(self._data) >= self.max_entries:
            # naive eviction
            self._data.pop(next(iter(self._data.keys())), None)
        self._data[key] = _CacheEntry(val=val, exp=now + self.ttl)
        return val


class KubernetesSecretResolver:
    """
    Resolve secrets from Kubernetes in two ways:

    1) File mount (simple & fast): `ref` is a file path containing JSON.
       Example: /var/run/secrets/fence/minio-dev.json

    2) API lookup (flexible): `ref` has the form `k8s://<namespace>/<secret-name>[:<key>]`.
       - If <key> is omitted, use the secret's single key.
       - Secret data is base64-decoded; the chosen key should contain JSON payload.

    Configure mode with env:
      - FENCE_K8S_SECRET_MODE = "mount" | "api" (default: "mount")
      - FENCE_K8S_NAMESPACE (default: POD namespace via /var/run/secrets/kubernetes.io/serviceaccount/namespace)
    """
    def __init__(self, ttl_seconds: int = 600):
        self.cache = TimedCache(ttl_seconds=ttl_seconds)
        self.mode = os.getenv("FENCE_K8S_SECRET_MODE", "mount").lower()
        self.default_ns = os.getenv("FENCE_K8S_NAMESPACE") or self._read_pod_namespace()

        # Initialize in-cluster if API mode is requested
        self._k8s = None
        if self.mode == "api":
            if config is None or client is None:
                raise RuntimeError("kubernetes package not available; install kubernetes to use API mode")
            try:
                config.load_incluster_config()
            except Exception:
                # Allow local dev (falls back to default kubeconfig)
                try:
                    config.load_kube_config()  # type: ignore
                except Exception as e:
                    raise RuntimeError(f"Cannot load Kubernetes config: {e}")
            self._k8s = client.CoreV1Api()

    def _read_pod_namespace(self) -> Optional[str]:
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return None

    def get(self, ref: str, version: Optional[str] = None) -> Mapping[str, str]:
        key = f"{self.mode}:{ref}:{version or 'latest'}"
        return self.cache.get(key, lambda: self._load(ref, version))

    def _load(self, ref: str, version: Optional[str]) -> Dict[str, str]:
        if self.mode == "mount" or not ref.startswith("k8s://"):
            with open(ref, "r", encoding="utf-8") as f:
                payload = f.read()
            return self._to_dict(payload)

        ns, name, key = self._parse_k8s_ref(ref)
        if not self._k8s:
            raise RuntimeError("Kubernetes client not initialized")
        sec = self._k8s.read_namespaced_secret(name=name, namespace=ns)
        if not sec.data:
            raise ValueError(f"Secret {ns}/{name} has no data")
        if key is None:
            if len(sec.data) != 1:
                raise ValueError(f"Secret {ns}/{name} has multiple keys; specify one in ref")
            key = next(iter(sec.data.keys()))
        if key not in sec.data:
            raise KeyError(f"Secret key '{key}' not found in {ns}/{name}")
        decoded = base64.b64decode(sec.data[key]).decode("utf-8")
        return self._to_dict(decoded)

    def _parse_k8s_ref(self, ref: str):
        raw = ref[len("k8s://"):]
        ns = self.default_ns
        key = None
        if "/" in raw:
            ns_part, rest = raw.split("/", 1)
            ns = ns_part or ns
        else:
            rest = raw
        if ":" in rest:
            name, key = rest.split(":", 1)
        else:
            name = rest
        if not ns:
            raise ValueError("Namespace is not set and not provided in ref; set FENCE_K8S_NAMESPACE or use k8s://<ns>/...")
        return ns, name, key

    def _to_dict(self, payload: str) -> Dict[str, str]:
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("Secret payload must be a JSON object mapping")
        return data
