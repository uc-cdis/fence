# Mock Fence (Admin Routes Only)

A minimal Flask app exposing the *new bucket admin routes* proposed for Fence:
- `GET /admin/buckets`
- `POST /admin/buckets`
- `PATCH /admin/buckets/{name}`
- `DELETE /admin/buckets/{name}` (soft-suspend)

## Run locally (SQLite)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r mock_fence/requirements.txt
DATABASE_URL=sqlite:///./mock_fence.db python -m mock_fence.app
# open http://localhost:8080/healthz
```

## With docker-compose (Postgres)
Update `docker-compose.yaml` to use the `mock-fence` service:

```yaml
  mock-fence:
    image: python:3.11-slim
    depends_on:
      - db
    working_dir: /app
    command: bash -lc "pip install -r mock_fence/requirements.txt && python -m mock_fence.app"
    environment:
      DATABASE_URL: "postgresql+psycopg2://fence:fence@db:5432/fence"
    ports:
      - "8080:8080"
    volumes:
      - ./:/app
```

Seed DB:
```bash
make seed-db
```

## Example payloads
```json
POST /admin/buckets
{
  "id": "11111111-1111-4111-8111-111111111111",
  "name": "dev-aws-dataset",
  "provider": "aws",
  "region": "us-west-2",
  "auth_mode": "role",
  "role_arn": "arn:aws:iam::123:role/gen3-bucket-access",
  "status": "active"
}
```





### Multipart upload (large files)

1) **Init**
```
POST /sign/multipart/init
{
  "bucket": "dev-minio-dataset",
  "key": "big/file.bin",
  "content_type": "application/octet-stream"
}
-> { "upload_id": "XYZ...", "bucket": "dev-minio-dataset", "key": "big/file.bin" }
```

2) **Upload each part** (repeat per part number)
```
POST /sign/multipart/part
{
  "bucket": "dev-minio-dataset",
  "key": "big/file.bin",
  "upload_id": "XYZ...",
  "part_number": 1,
  "expires": 900
}
-> { "url": "https://...", "method": "PUT", "part_number": 1 }
```

3) **Complete**
```
POST /sign/multipart/complete
{
  "bucket": "dev-minio-dataset",
  "key": "big/file.bin",
  "upload_id": "XYZ...",
  "parts": [
    {"PartNumber":1,"ETag":"\"etag1\""},
    {"PartNumber":2,"ETag":"\"etag2\""}
  ]
}
-> S3 completion response (ETag, Location, etc.)
```
