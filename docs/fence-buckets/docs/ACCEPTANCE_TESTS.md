# Acceptance Tests

> These can be executed against a dev stack (docker-compose) or a staging cluster.
> Steps assume AWS SM (via Localstack in compose).

## AT1: Create role-based AWS bucket and presign works
**Given** the DB schema is applied  
**And** Fence is running with dynamic buckets enabled  
**When** I `POST /admin/buckets` with:
```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "name": "dev-aws-dataset",
  "provider": "aws",
  "region": "us-west-2",
  "auth_mode": "role",
  "role_arn": "arn:aws:iam::000000000000:role/gen3-bucket-access"
}
```
**Then** `GET /admin/buckets` lists `dev-aws-dataset` as `active`  
**And** a presign call for that bucket returns a valid URL (mock in tests).

## AT2: Create MinIO (static) bucket and read secret
**Given** a secret exists at `gen3/fence/minio/example` with JSON keys  
**When** I `POST /admin/buckets` with:
```json
{
  "id": "22222222-2222-4222-8222-222222222222",
  "name": "dev-minio-dataset",
  "provider": "minio",
  "endpoint": "http://minio.internal:9000",
  "region": "us-west-2",
  "auth_mode": "static",
  "secret_ref": "arn:aws:secretsmanager:us-west-2:000000000000:secret:gen3/fence/minio/example"
}
```
**Then** presign succeeds using credentials from the secret

## AT3: Rotation picks up new secret version
**Given** AT2 is satisfied  
**When** a new secret version is written with different keys  
**And** I wait longer than `FENCE_SECRET_CACHE_TTL_SECONDS`  
**Then** presign continues to succeed and uses the new keys (verified via MinIO logs or mock)

## AT4: Suspend bucket
**Given** bucket exists and presigns work  
**When** I `DELETE /admin/buckets/dev-minio-dataset`  
**Then** presign attempts fail with 403/409

## AT5: Back-compat fallback
**Given** the registry table is empty  
**When** I restart Fence with legacy YAML (`S3_BUCKETS`) populated  
**Then** presigns continue to work for those YAML buckets
