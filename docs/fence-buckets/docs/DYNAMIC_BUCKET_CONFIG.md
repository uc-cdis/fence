
# How bucket configs are read today

* ## In Fence (the AuthN/AuthZ service)

  * Fence loads its runtime configuration from a YAML file (commonly called `fence-config.yaml`) that it finds in its configured search paths; the README points to these search dirs and the `cfg_help.py` helper for multi‑file setups. ([GitHub][1])
  * Bucket settings live in that YAML. Two keys matter for uploads/downloads:

    * `S3_BUCKETS`: the list/map of S3 buckets Fence “knows about” for signed URL generation and object operations. (Referenced in PRs/notes and code comments.) ([GitHub][2])
    * `ALLOWED_DATA_UPLOAD_BUCKETS`: the explicit allow‑list for where end‑users may upload (otherwise uploads are rejected). This is defined in `config-default.yaml`. There is also a historical `DATA_UPLOAD_BUCKET` default. ([GitHub][3])
  * Recent Fence releases also added support for selecting an upload bucket (one of the configured `S3_BUCKETS`) when creating records / multipart uploads. ([GitHub][4])

* ## In gen3-helm (deployment)

  * You pass Fence config to the chart under `fence.FENCE_CONFIG` in the Helm `values.yaml`; the chart renders this into the running Fence pod (ConfigMap/Secret). ([GitHub][5])
  * A related (separate) Helm value points to `user.yaml` in S3 for user/group/role sync (not buckets, but shows how the chart reads S3‑hosted config): `fence.usersync.userYamlS3Path`. ([GitHub][6])

In short: **Buckets are declared in Fence’s YAML (`S3_BUCKETS`, `ALLOWED_DATA_UPLOAD_BUCKETS`), and Helm just injects that YAML into the pod.** Fence then uses those structures when issuing short‑lived creds and building presigned URLs.

---

# Strategy: make bucket configs dynamic (admin‑friendly, multi‑tenant, safe)

Below is a pragmatic path that doesn’t require a Helm redeploy for every bucket tweak, and keeps security tight.

## 1) Data model & storage (source of truth)

Define a **Bucket Registry** (one table or document collection) managed by Fence:

* **Schema (suggested fields)**
  `name`, `provider` (`aws`, `gcp`, `minio`), `region`, `endpoint` (for S3‑compatible), `arn/role` (for AWS STS), `kms_key`, `prefix_allowlist` (optional), `allowed_ops` (`read`, `write`, `delete`, `multipart`), `owner_project`, `labels/tags`, `status` (`active`, `suspended`), **policy binding** (Arborist resource path(s) this bucket/prefix maps to).
* **Where stored**: new Fence DB table(s). This removes Helm as the config choke‑point.

Fence already separates “known buckets” from “allowed upload targets”; keep that logic, but drive both from the registry rather than static YAML (`S3_BUCKETS` + `ALLOWED_DATA_UPLOAD_BUCKETS`). (Fence’s static keys documented in `config-default.yaml` and release notes.) ([GitHub][3])

## 2) Management API

Add **admin‑only REST endpoints** in Fence:

* `POST /admin/buckets` create
* `PUT/PATCH /admin/buckets/{name}` update (rotate role ARN/KMS, add prefixes, etc.)
* `GET /admin/buckets` list/filter
* `DELETE /admin/buckets/{name}` soft‑delete (status→suspended)

These mutations should:

* Validate access: the caller must have an Arborist policy that allows bucket‑admin actions.
* Validate cloud side: check the role ARN exists and can list the bucket, verify KMS key policy, and (optionally) dry‑run a presign.

## 3) Runtime plumbing in Fence

* **Loader**: on startup, Fence loads registry entries into an in‑memory map (compatible with places that expect `S3_BUCKETS`). Replace reads of `fence_config.S3_BUCKETS`/`ALLOWED_DATA_UPLOAD_BUCKETS` with a **registry service** (with a short cache TTL, e.g., 60s).
* **Hot reload**: expose `POST /admin/buckets/reload` (admin only) or just rely on the TTL cache; no pod restart.
* **Back‑compat**: if the DB is empty, fall back to YAML `S3_BUCKETS` and `ALLOWED_DATA_UPLOAD_BUCKETS` so existing installs still work. (The presence of these keys and their behavior are documented in Fence.) ([GitHub][3])

## 4) Credentials & secrets

* Prefer **role‑based access** (AWS STS `AssumeRole`) over static keys; store only role ARNs in the registry. (Fence already issues short‑lived cloud creds; keep that pattern.)
* If static creds are unavoidable, integrate with **AWS Secrets Manager / GCP Secret Manager** and reference by ARN/ID in the registry; fetch on use.
* For S3‑compatible endpoints (MinIO, on‑prem), allow custom `endpoint` with v4 signing.

## 5) Policy binding & enforcement

* Each bucket or prefix should map to an **Arborist resource** (e.g., `/data/bucket/<name>` or `/data/bucket/<name>/<prefix>`).
* On presign/upload, Fence already checks policies; extend the check to match the dynamic registry entry + caller’s policies. (This mirrors the existing “allowed buckets” enforcement, but now driven by DB rather than YAML.) ([GitHub][3])

## 6) User‑facing UX

* Add a small **“Bucket Manager”** page (portal admin or a separate React micro‑UI) where authorized project owners can:

  * Register a bucket (supply role ARN / endpoint, select allowed ops, optional prefixes).
  * See health checks (policy OK, KMS OK, can list, can presign).
  * Toggle “allow uploads”.
* Optionally add a **project binding** so buckets appear in the correct projects’ submission/upload UI.

## 7) Migration plan

1. **Phase 0**: Keep YAML as the seed source; ship a one‑time migration CLI (`fence-create sync-buckets-from-yaml`) that writes entries to the DB.
2. **Phase 1**: Fence reads from DB first, falls back to YAML.
3. **Phase 2**: Deprecate YAML bucket keys in `fence-config.yaml` and keep only DB (Helm remains for other settings).

## 8) Ops & safety

* **Audit**: log every create/update/delete with actor, diff, and cloud validation result.
* **Drift detection**: nightly job verifies that the role policy/KMS match what’s recorded; alert on drift.
* **Constraints**: optional org‑level constraints (e.g., enforce server‑side encryption, deny public buckets, enforce CLI multipart for objects > N GiB).
* **Testing**: a dry‑run endpoint that simulates a presign/upload with a service token to validate a new bucket before enabling.

---

## Why this works well with Gen3 today

* It **doesn’t fight Helm**: Helm remains for cluster bootstrapping; buckets become data, not infrastructure. The chart continues to inject the base Fence config, while bucket changes flow through Fence’s DB/API live. ([GitHub][5])
* It **preserves Fence’s semantics**: the documented keys (`S3_BUCKETS`, `ALLOWED_DATA_UPLOAD_BUCKETS`, `DATA_UPLOAD_BUCKET`) stay conceptually the same; you just move the live set into a registry the service controls, matching features introduced across recent releases that let callers pick an allowed upload bucket. ([GitHub][3])


[1]: https://github.com/uc-cdis/fence/blob/master/README.md "fence/README.md at master · uc-cdis/fence · GitHub"
[2]: https://github.com/uc-cdis/fence/pull/1048?utm_source=chatgpt.com "Adds bucket parameter to indexd.make_signed_url #1048"
[3]: https://github.com/uc-cdis/fence/blob/master/fence/config-default.yaml?utm_source=chatgpt.com "fence/fence/config-default.yaml at master · uc-cdis/fence"
[4]: https://github.com/uc-cdis/fence/releases?utm_source=chatgpt.com "Releases: uc-cdis/fence - GitHub"
[5]: https://github.com/uc-cdis/gen3-helm "GitHub - uc-cdis/gen3-helm: Helm charts for Gen3 Deployments"
[6]: https://github.com/uc-cdis/gen3-helm/blob/master/helm/gen3/README.md "gen3-helm/helm/gen3/README.md at master · uc-cdis/gen3-helm · GitHub"
