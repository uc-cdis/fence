# Overview
Implementation‑level plan for integrating a secrets manager into the “dynamic buckets” design. 
AWS Secrets Manager and GCP Secret Manager as primary examples, and show how HashiCorp Vault or Kubernetes Secrets fit the same interface.

# Goals

* Keep **bucket metadata in Fence DB**, but keep **credentials in a secrets manager** (never in DB/Helm).
* Support **role‑based** access (preferred; no secrets needed) and **static‑key** access (S3‑compatible, MinIO, legacy).
* Enable **rotation** without pod restarts, with **zero‑downtime cache refresh**.
* Maintain **least privilege** and strong **audit**.

# What is (and isn’t) a “secret”

* **Not secrets**: AWS Role ARN, GCP service account email, KMS key ID/ARN, endpoint URL, region, bucket name, allowed ops.
* **Secrets** (store in manager): Access key & secret key (S3/MinIO), GCP service account JSON (only if you can’t use Workload Identity), TLS client cert/key for S3 endpoints requiring mTLS, webhook tokens for rotation callbacks (if any).

# Data model extension (Fence DB)

Add fields to the Bucket Registry (or a companion `bucket_credentials` table):

```
id (uuid)
bucket_name
provider           -- 'aws' | 'gcp' | 's3_compatible' | 'minio' | 'azure_blob' (future)
auth_mode          -- 'role' | 'static' | 'workload_identity'
secrets_backend    -- 'aws_sm' | 'gcp_sm' | 'vault' | 'k8s' | null
secret_ref         -- opaque reference: e.g., AWS: 'arn:aws:secretsmanager:...:secret:my/minio-ABC123'
secret_version     -- optional pin; null => latest
kms_key_ref        -- not secret, but useful policy check
endpoint           -- for s3-compatible
created_at / updated_at
status             -- active | suspended
```

Admins **only** store `secret_ref` (and optional version). They never paste keys into Fence DB.

# Pluggable resolver interface

Introduce a tiny abstraction in Fence, used wherever credentials are needed:

```python
class SecretResolver(Protocol):
    def get(self, ref: str, version: str | None = None) -> Mapping[str, str]: ...
    def put(self, ref: str, payload: Mapping[str, str]) -> None: ...        # optional (admin flows)
```

Concrete implementations:

* `AwsSecretsManagerResolver`
* `GcpSecretManagerResolver`
* `VaultResolver`
* `KubernetesSecretResolver`

Configured via `FENCE_SECRETS_BACKEND` (e.g., `aws_sm`) and provider‑specific env (e.g., region). The resolver is injected into a `BucketCredentialsService`.

# AuthN for the Fence pod to read secrets

* **AWS**: use IRSA (IAM Role for Service Accounts). The Fence pod’s KSA is annotated to assume a tightly scoped IAM role that can `secretsmanager:GetSecretValue` **only** for allowed paths (e.g., `/gen3/fence/*`).
* **GCP**: use Workload Identity / GKE; grant `Secret Manager Secret Accessor` on specific secrets.
* **Vault**: use Kubernetes auth method; map Fence service account → Vault role with a path policy.
* **Kubernetes Secrets**: Fence reads via API (RBAC to a single namespace/label selector) or mounts as files (downside: rotation latency).

# Secret shape conventions

Use a consistent JSON payload per provider so Fence can be provider‑agnostic:

* **S3/MinIO static**:

  ```json
  {
    "access_key_id": "…",
    "secret_access_key": "…",
    "session_token": "…",     // optional, if short‑lived
    "ca_bundle_pem": "…",     // optional, if custom CA
    "client_cert_pem": "…",   // optional, mTLS
    "client_key_pem": "…"     // optional, mTLS
  }
  ```

* **GCP service account (legacy)**:

  ```json
  { "service_account_key_json": "{...the entire JSON...}" }
  ```

Fence code reads this JSON and configures an SDK client accordingly.

# Retrieval lifecycle (fast path)

1. Request comes in for presign/upload on bucket `B`.
2. Fence authorizes via Arborist and resolves bucket `B` → registry record.
3. If `auth_mode = role` (AWS/GCP), **no secret fetch**:

   * **AWS**: call STS `AssumeRole` (optionally with external ID).
   * **GCP**: exchange workload identity for target SA (short‑lived creds).
4. If `auth_mode = static`, resolve `secret_ref` through `SecretResolver`.
5. **Cache** the decrypted secret in‑process with:

   * Key: `(secret_ref, version-or-latest)`
   * TTL: short (e.g., 5–10 minutes) + jitter
   * Size bound + LRU
6. Build a cloud client (boto3/MinIO SDK/google‑cloud‑storage) and perform the operation (or pre‑sign).

**Note**: never log secret contents; log only `secret_ref` and last4 of access key if needed for debugging.

# Rotation strategies

* **AWS Secrets Manager**: enable rotation on the secret (Lambda or native rotation for RDS‑like targets; for MinIO, supply a custom Lambda that talks to MinIO to rotate keys).

  * Option A: keep `secret_version` **empty** and always read `AWSCURRENT`. No DB change needed on rotation.
  * Option B: pin `secret_version` to a specific version; an admin/API updates the DB after rotation to “flip” traffic. (Blue/green for sensitive cases.)
* **GCP Secret Manager**: create new versions; Fence reads `latest` unless pinned.
* **Vault**: store credentials as dynamic secrets (leased). Fence respects TTL and refreshes before lease expiry; no rotation Lambda needed.

Fence cache respects version/lease TTL so new versions are picked up automatically.

# Admin flows (safety and UX)

* **Create bucket (static)**:

  1. Admin calls `POST /admin/buckets` with metadata **and** either:

     * `secret_ref` of a pre‑provisioned secret, or
     * a flag `create_secret: true` + payload of keys (only for bootstrap; Fence will immediately **write** to the secrets manager using its writer role and **discard** the plaintext).
  2. Fence validates the creds by listing the bucket or performing a dry‑run presign.
* **Rotate**:

  * If the backend supports managed rotation (AWS/GCP): use it and rely on “latest” semantics.
  * If manual: upload new version, then `PATCH /admin/buckets/{id}` to pin to the new `secret_version`. Fence cache expires and starts using the new material.
* **Suspend**:

  * `status=suspended` prevents fetch/presign; Fence returns 403/409.

# Least‑privilege IAM / policies

* AWS IAM role for Fence secrets access:

  * Allow `secretsmanager:GetSecretValue` for `arn:aws:secretsmanager:…:secret:gen3/fence/*`.
  * Deny `CreateSecret`, `DeleteSecret`, `TagResource` in runtime role (use a **separate admin role** for writes).
* GCP: grant `roles/secretmanager.secretAccessor` on a **single project** and narrow names like `projects/X/secrets/gen3-fence-*`.
* Vault: policy permits only `read` on `kv/gen3/fence/*`.

# Ops hardening

* **FIPS/crypto**: rely on cloud KMS backing; no custom crypto in Fence.
* **Memory hygiene**: store secrets only in ephemeral dicts; avoid long‑lived globals; cap cache size; consider `memfd` if you mount files (k8s secrets).
* **Audit**: log (INFO) `secret_ref` reads (not values), caller, and purpose (“presign”, “multipart-init”) with sampling to reduce noise.
* **Drift checks**: nightly job to validate the secret still works (list bucket / sts assume) and KMS policies match expectations.

# Minimal code sketch (AWS example)

```python
# resolver.py
import json
import boto3
from functools import lru_cache
from time import monotonic

class TimedCache:
    def __init__(self, ttl_seconds=600):
        self.ttl = ttl_seconds
        self._data = {}
    def get(self, key, loader):
        now = monotonic()
        ent = self._data.get(key)
        if ent and now < ent["exp"]:
            return ent["val"]
        val = loader()
        self._data[key] = {"val": val, "exp": now + self.ttl}
        return val

class AwsSecretsManagerResolver:
    def __init__(self, region: str | None = None, ttl=600):
        self.sm = boto3.client("secretsmanager", region_name=region)
        self.cache = TimedCache(ttl)
    def get(self, ref: str, version: str | None = None) -> dict:
        key = f"{ref}:{version or 'latest'}"
        def _load():
            kwargs = {"SecretId": ref}
            if version:
                kwargs["VersionId"] = version
            resp = self.sm.get_secret_value(**kwargs)
            payload = resp.get("SecretString") or resp.get("SecretBinary")
            if isinstance(payload, (bytes, bytearray)):
                payload = payload.decode("utf-8")
            return json.loads(payload)
        return self.cache.get(key, _load)
```

Using it inside the bucket client factory:

```python
def make_s3_client(bucket):
    if bucket.auth_mode == "role":
        # AssumeRole into target account (no secret fetch)
        creds = assume_role(bucket.role_arn, external_id=bucket.external_id)
        return boto3.client("s3",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            endpoint_url=bucket.endpoint, region_name=bucket.region)
    else:
        secret = secrets_resolver.get(bucket.secret_ref, bucket.secret_version)
        return boto3.client("s3",
            aws_access_key_id=secret["access_key_id"],
            aws_secret_access_key=secret["secret_access_key"],
            aws_session_token=secret.get("session_token"),
            endpoint_url=bucket.endpoint, region_name=bucket.region)
```

# Example end‑to‑end flows

### A) AWS, role‑based (preferred)

* Admin registers bucket with `auth_mode=role`, `role_arn=arn:aws:iam::123:role/gen3-bucket-access`.
* Fence uses IRSA to call STS AssumeRole for each operation → presign. **No secrets manager usage**.

### B) MinIO (static keys), with rotation

* Admin creates `gen3/fence/minio/my-dataset` in AWS Secrets Manager and stores `access_key_id`/`secret_access_key`.
* Admin registers bucket with `auth_mode=static`, `secrets_backend=aws_sm`, `secret_ref=arn:…:secret:gen3/fence/minio/my-dataset`.
* A rotation Lambda periodically rotates keys in MinIO and updates the secret (**same ARN, new version**).
* Fence cache expires → reads `AWSCURRENT` → uses new keys automatically.

### C) GCP, Workload Identity (no long‑term JSON keys)

* Admin registers bucket with `auth_mode=workload_identity`, `gcp_service_account=email`, **no secret\_ref**.
* Fence exchanges its GKE identity for short‑lived creds to act as that SA. **No secret stored**.

# Migration & Helm touch‑points

* Helm: add env to Fence:

  * `FENCE_SECRETS_BACKEND=aws_sm|gcp_sm|vault|k8s`
  * Backend params (e.g., AWS region, Vault address/role)
* No configmaps with secrets. If you currently have static creds in `fence-config.yaml`, run a one‑time **migration CLI**:

  * Creates a secret in the chosen backend
  * Rewrites the bucket registry row to reference `secret_ref`
  * Removes plaintext from disk
* RBAC/IAM: provision the pod’s identity to read only the allowed path in the secrets backend.

---

If you want, I can turn this into:

* a PR outline for Fence (module names, interfaces, config keys),
* a Helm changeset (values, IRSA/Workload Identity snippets),
* and a small rotation Lambda (MinIO) example.
