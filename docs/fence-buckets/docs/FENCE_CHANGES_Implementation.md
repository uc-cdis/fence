
# 1) Database schema (SQL)

This schema separates bucket **identity**, optional **prefix scoping**, and **policy bindings** (how a bucket/prefix maps to Arborist resources and allowed ops). It also keeps secrets **out** of the DB—only an external reference is stored.

```sql
-- 001_dynamic_buckets.sql

-- Buckets are data, not infra. Keep them normalized and auditable.
CREATE TABLE IF NOT EXISTS bucket (
  id               UUID PRIMARY KEY,
  name             TEXT UNIQUE NOT NULL,                        -- human name, used by API
  provider         TEXT NOT NULL CHECK (provider IN ('aws','gcp','minio','s3_compatible')),
  region           TEXT,
  endpoint         TEXT,                                        -- for S3-compatible / MinIO
  auth_mode        TEXT NOT NULL CHECK (auth_mode IN ('role','static','workload_identity')),
  role_arn         TEXT,                                        -- AWS STS role (if auth_mode='role')
  secret_ref       TEXT,                                        -- external secret reference (ARN/path); no plaintext
  secret_version   TEXT,                                        -- optional pin; NULL => latest
  owner_project    TEXT,                                        -- optional logical grouping
  labels           JSONB DEFAULT '{}'::jsonb,
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bucket_name ON bucket(name);
CREATE INDEX IF NOT EXISTS idx_bucket_status ON bucket(status);
CREATE INDEX IF NOT EXISTS idx_bucket_owner ON bucket(owner_project);

-- Optional: restrict ops to paths within a bucket (fine-grained control)
CREATE TABLE IF NOT EXISTS bucket_prefix (
  id          UUID PRIMARY KEY,
  bucket_id   UUID NOT NULL REFERENCES bucket(id) ON DELETE CASCADE,
  prefix      TEXT NOT NULL,                        -- e.g., 'incoming/', 'teams/alpha/'
  UNIQUE(bucket_id, prefix)
);

-- Bind a bucket or prefix to Arborist resources + allowed ops.
-- Examples:
--   resource_path: "/data/program/DEV/project/ABC"
--   allowed_ops:   {"read": true, "write": true, "delete": false, "multipart": true}
CREATE TABLE IF NOT EXISTS bucket_policy_binding (
  id             UUID PRIMARY KEY,
  bucket_id      UUID NOT NULL REFERENCES bucket(id) ON DELETE CASCADE,
  bucket_prefix_id UUID REFERENCES bucket_prefix(id) ON DELETE CASCADE,
  resource_path  TEXT NOT NULL,
  allowed_ops    JSONB NOT NULL,          -- shape: {"read":true,"write":true,"delete":false,"multipart":true}
  UNIQUE(bucket_id, COALESCE(bucket_prefix_id::text, ''), resource_path)
);

-- Audit table (optional but recommended)
CREATE TABLE IF NOT EXISTS bucket_audit (
  id          BIGSERIAL PRIMARY KEY,
  bucket_id   UUID,
  actor       TEXT NOT NULL,              -- user or service account
  action      TEXT NOT NULL,              -- create|update|suspend|resume
  diff        JSONB,                      -- before/after or patch payload
  at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- updated_at trigger (Postgres)
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_bucket_updated_at ON bucket;
CREATE TRIGGER trg_bucket_updated_at
BEFORE UPDATE ON bucket
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
```

**Alembic note:** put this in a migration (`versions/XXXX_dynamic_buckets.py`) and wire it into Fence’s migration chain.

---

# 2) Endpoint specs (admin‑only)

Base path: `/admin/buckets` (new blueprint). Authz: caller must hold an Arborist permission like `bucket_admin` (name your policy as you prefer).

## List buckets

```
GET /admin/buckets?status=active|suspended&owner_project=DEV-100
```

**200**

```json
[
  {
    "id": "11111111-1111-4111-8111-111111111111",
    "name": "dev-aws-dataset",
    "provider": "aws",
    "region": "us-west-2",
    "endpoint": null,
    "auth_mode": "role",
    "role_arn": "arn:aws:iam::123:role/gen3-bucket-access",
    "secret_ref": true,                       // boolean: present or not
    "secret_version": null,
    "status": "active",
    "owner_project": "DEV-100",
    "labels": {"env":"dev"}
  }
]
```

## Create bucket

```
POST /admin/buckets
Content-Type: application/json
```

Body (examples):

* **AWS role-based (preferred)**

```json
{
  "name": "dev-aws-dataset",
  "provider": "aws",
  "region": "us-west-2",
  "auth_mode": "role",
  "role_arn": "arn:aws:iam::123:role/gen3-bucket-access",
  "owner_project": "DEV-100",
  "labels": {"env":"dev"}
}
```

* **MinIO static**

```json
{
  "name": "dev-minio-dataset",
  "provider": "minio",
  "endpoint": "https://minio.internal:9000",
  "region": "us-west-2",
  "auth_mode": "static",
  "secret_ref": "arn:aws:secretsmanager:us-west-2:000000000000:secret:gen3/fence/minio/dev-minio-dataset",
  "owner_project": "DEV-100"
}
```

**201**

```json
{"ok": true, "id":"...", "name":"dev-aws-dataset"}
```

**409** name exists, **400** validation errors.

## Update bucket (partial)

```
PATCH /admin/buckets/{name}
```

Body can include any mutable fields: `region`, `endpoint`, `role_arn`, `secret_ref`, `secret_version`, `status`, `labels`, `owner_project`.

**200** `{"ok": true}` or **404**.

## Suspend / resume

```
DELETE /admin/buckets/{name}   -> sets status='suspended'
POST   /admin/buckets/{name}/resume  -> sets status='active'
```

**200** `{"ok": true, "status": "suspended"}`

## Prefix binding (optional granularity)

```
POST /admin/buckets/{name}/prefixes
{
  "prefix": "incoming/"
}
```

```
POST /admin/buckets/{name}/bindings
{
  "prefix": "incoming/",         // optional
  "resource_path": "/data/program/DEV/project/ABC",
  "allowed_ops": {"read": true, "write": true, "multipart": true, "delete": false}
}
```

**200** `{"ok": true, "binding_id":"..."}`

## Validate (dry‑run)

```
POST /admin/buckets/{name}/validate
```

Performs:

* For `role`: STS AssumeRole, list bucket (or pre‑sign a HEAD)
* For `static`: fetch secret via resolver, list bucket or pre‑sign
  Returns **200** with details or **400** with the failure reason.

---

# 3) Patch points in Fence (swap config lookups → registry accessor)

Below is a surgical list of common places where Fence reads `current_app.config["S3_BUCKETS"]`, `ALLOWED_DATA_UPLOAD_BUCKETS`, or the legacy `DATA_UPLOAD_BUCKET`, and what to replace them with. (Names are illustrative—exact file paths can vary across Fence versions; the pattern is consistent.)

## 3.1 Add a registry + client “service” (new module)

Create a small service with caching that:

* Resolves a bucket by `name`
* Produces a cloud client (boto3 or S3‑compatible) either by **assuming a role** or **fetching a secret** via the resolver
* Checks “allowed ops” for a user (by Arborist resource paths)

**`fence/services/buckets.py`**

```python
from __future__ import annotations
from flask import current_app
from .secrets.resolver import AwsSecretsManagerResolver  # or pluggable
from .models import db, Bucket, BucketPolicyBinding   # SQLAlchemy models
from cdispyutils.auth.arborist import ArboristClient  # existing Fence helper

class BucketRegistry:
    def __init__(self, secret_backend="aws_sm", bucket_ttl=60, secret_ttl=600):
        self._cache = TimedCache(ttl_seconds=bucket_ttl)
        self._secrets = AwsSecretsManagerResolver(ttl_seconds=secret_ttl)

    def get(self, name: str) -> Bucket:
        return self._cache.get(f"bucket:{name}", lambda: db.session.query(Bucket).filter_by(name=name, status="active").one())

    def ensure_allowed(self, bucket: Bucket, user_jwt: dict, op: str, key: str | None = None):
        """Check Arborist policy for op on bucket/prefix."""
        # Build list of candidate resource paths from bindings (prefix match if key provided)
        paths = self._candidate_resource_paths(bucket, key)
        arborist: ArboristClient = current_app.arborist
        for path in paths:
            if arborist.has_permission(user_jwt, {"service": "fence", "method": op, "resource": path}):
                return True
        raise Forbidden("not authorized for op on this bucket")

    def make_s3_client(self, bucket: Bucket):
        import boto3
        if bucket.auth_mode == "role":
            sts = boto3.client("sts")
            resp = sts.assume_role(RoleArn=bucket.role_arn, RoleSessionName="fence-bucket-session")
            c = boto3.client("s3",
                aws_access_key_id=resp["Credentials"]["AccessKeyId"],
                aws_secret_access_key=resp["Credentials"]["SecretAccessKey"],
                aws_session_token=resp["Credentials"]["SessionToken"],
                region_name=bucket.region, endpoint_url=bucket.endpoint)
            return c
        else:
            secret = self._secrets.get(bucket.secret_ref, bucket.secret_version)
            c = boto3.client("s3",
                aws_access_key_id=secret["access_key_id"],
                aws_secret_access_key=secret["secret_access_key"],
                aws_session_token=secret.get("session_token"),
                region_name=bucket.region, endpoint_url=bucket.endpoint)
            return c

    # ... plus helpers: _candidate_resource_paths, cache, etc.
```

Initialize a singleton at app startup:

```python
# in app factory
from fence.services.buckets import BucketRegistry
current_app.bucket_registry = BucketRegistry(
    secret_backend=os.getenv("FENCE_SECRETS_BACKEND", "aws_sm"),
    bucket_ttl=int(os.getenv("FENCE_BUCKET_CACHE_TTL_SECONDS", "60")),
    secret_ttl=int(os.getenv("FENCE_SECRET_CACHE_TTL_SECONDS", "600")),
)
```

## 3.2 Upload initialization (replaces `ALLOWED_DATA_UPLOAD_BUCKETS`)

**Before (typical):**

```python
cfg = current_app.config
allowed = set(cfg.get("ALLOWED_DATA_UPLOAD_BUCKETS", []))
target = request.json["bucket"]
if target not in allowed:
    return {"message":"bucket not allowed"}, 403
# build s3 client using cfg["S3_BUCKETS"][target]...
```

**After (dynamic):**

```python
target = request.json["bucket"]  # or default from request context
br = current_app.bucket_registry
bucket = br.get(target)

# authz: ensure write/multipart is allowed for this caller
br.ensure_allowed(bucket, user_jwt=current_token, op="write", key=request.json.get("key"))

s3 = br.make_s3_client(bucket)
# continue: initiate multipart or single PUT using 's3' and 'bucket'
```

**Where:** endpoints like `/data/upload`, `/s3-multipart`, or similar upload initializers.

## 3.3 Download / presigned URL (replaces `S3_BUCKETS` lookups)

**Before:**

```python
cfg = current_app.config
bucket_name = resolve_from_metadata(...)  # or a param
bucket_cfg = cfg["S3_BUCKETS"][bucket_name]
# create client from static config...
```

**After:**

```python
br = current_app.bucket_registry
bucket = br.get(bucket_name)
br.ensure_allowed(bucket, user_jwt=current_token, op="read", key=request.args.get("key"))
s3 = br.make_s3_client(bucket)
# pre-sign via s3.generate_presigned_url(...)
```

**Where:** endpoints that issue download presigns (e.g., `/data/download`, `/s3/download`).

## 3.4 Default upload bucket (replaces `DATA_UPLOAD_BUCKET`)

Fence sometimes derives a “default” upload bucket. Replace:

**Before:**

```python
default_bucket = current_app.config.get("DATA_UPLOAD_BUCKET")
```

**After:** drive from registry by **owner\_project** (or a label) if you want a sane default.

```python
def pick_default_bucket(user_project: str) -> str:
    # Prefer a bucket with matching owner_project and status=active
    b = db.session.query(Bucket).filter_by(owner_project=user_project, status="active").first()
    return b.name if b else None
```

## 3.5 Background jobs and utilities

Any helper that previously iterated `S3_BUCKETS` (e.g., health checks, migration scripts) should call the registry:

```python
for b in db.session.query(Bucket).filter_by(status="active").all():
    s3 = current_app.bucket_registry.make_s3_client(b)
    # health check: s3.list_buckets() / head_bucket(...)
```

---

# 4) Minimal OpenAPI additions (merge into Fence spec)

Append to fence's OpenAPI:

```yaml
paths:
  /admin/buckets:
    get:
      summary: List buckets
      security: [{ bearerAuth: [] }]
      parameters:
        - in: query
          name: status
          schema: { type: string, enum: [active, suspended] }
        - in: query
          name: owner_project
          schema: { type: string }
      responses: { '200': { description: OK } }
    post:
      summary: Create bucket
      security: [{ bearerAuth: [] }]
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/BucketCreate' }
      responses: { '201': { description: Created } }

  /admin/buckets/{name}:
    patch:
      summary: Update bucket
      security: [{ bearerAuth: [] }]
      parameters: [{ in: path, name: name, required: true, schema: { type: string } }]
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/BucketUpdate' }
      responses: { '200': { description: OK }, '404': { description: Not Found } }
    delete:
      summary: Suspend bucket
      security: [{ bearerAuth: [] }]
      parameters: [{ in: path, name: name, required: true, schema: { type: string } }]
      responses: { '200': { description: OK }, '404': { description: Not Found } }

  /admin/buckets/{name}/resume:
    post:
      summary: Resume bucket
      security: [{ bearerAuth: [] }]
      parameters: [{ in: path, name: name, required: true, schema: { type: string } }]
      responses: { '200': { description: OK }, '404': { description: Not Found } }

  /admin/buckets/{name}/validate:
    post:
      summary: Validate bucket configuration
      security: [{ bearerAuth: [] }]
      responses: { '200': { description: OK } }

components:
  schemas:
    BucketCreate:
      type: object
      required: [name, provider, auth_mode]
      properties:
        name: { type: string }
        provider: { type: string, enum: [aws, gcp, minio, s3_compatible] }
        region: { type: string }
        endpoint: { type: string, nullable: true }
        auth_mode: { type: string, enum: [role, static, workload_identity] }
        role_arn: { type: string, nullable: true }
        secret_ref: { type: string, nullable: true }
        secret_version: { type: string, nullable: true }
        owner_project: { type: string, nullable: true }
        labels: { type: object, additionalProperties: true }
    BucketUpdate:
      type: object
      properties:
        region: { type: string }
        endpoint: { type: string, nullable: true }
        role_arn: { type: string, nullable: true }
        secret_ref: { type: string, nullable: true }
        secret_version: { type: string, nullable: true }
        status: { type: string, enum: [active, suspended] }
        owner_project: { type: string, nullable: true }
        labels: { type: object, additionalProperties: true }
```

---

# 5) Guardrails & notes

* **Feature flag**: gate dynamic buckets behind `FENCE_ENABLE_DYNAMIC_BUCKETS=true`. If `false` or registry empty → fall back to YAML keys.
* **Secrets**: never read from `FENCE_CONFIG`. Resolve via the secrets resolver only.
* **Cache**: keep short TTLs (60s buckets / 5–10 min secrets) and small LRU sizes.
* **Testing**: add integration tests that:

  * Seed DB with a role‑based bucket and verify download/upload presigns (mock STS).
  * Seed a static MinIO bucket using Localstack Secrets Manager and confirm rotation pickup after TTL.

