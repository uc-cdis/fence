# Use Cases and Acceptance Tests

## UC1: Register AWS bucket with AssumeRole
- **Given** Fence is running with dynamic buckets enabled
- **When** admin registers a bucket with `auth_mode=role`
- **Then** presign requests succeed using STS AssumeRole

✅ Acceptance Test: Create bucket via POST, verify presign works.

## UC2: Register MinIO bucket with static creds
- **Given** static creds in AWS Secrets Manager
- **When** admin registers bucket with `auth_mode=static` and `secret_ref`
- **Then** Fence fetches from SM and returns presigned URLs

✅ Acceptance Test: Rotate secret in SM, wait TTL, verify presign uses new keys.

## UC3: Suspend bucket
- **Given** bucket exists active
- **When** admin DELETEs `/admin/buckets/<name>`
- **Then** bucket marked suspended and presigns denied

✅ Acceptance Test: Attempt presign → 403.

## UC4: Migration from YAML
- **Given** S3_BUCKETS in legacy config
- **When** `fence-create sync-buckets-from-yaml` runs
- **Then** DB populated

✅ Acceptance Test: Compare YAML vs DB entries.

## UC5: Cache expiry & rotation
- **Given** cached secret
- **When** secret rotates upstream
- **Then** after TTL, Fence fetches new version

✅ Acceptance Test: Presign before vs after TTL with rotated secret.
