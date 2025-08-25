
from __future__ import annotations
import os
from typing import Any, Dict, Tuple, Optional
from flask import Blueprint, request, jsonify
import boto3
from botocore.client import Config as BotoConfig
from .models import SessionLocal, Bucket

try:
    from fence.secrets.k8s_resolver import KubernetesSecretResolver
except Exception:
    KubernetesSecretResolver = None  # type: ignore

bp = Blueprint("signing", __name__)

def _make_s3_client_for_bucket(b: Bucket) -> Any:
    """Build and return a boto3 S3 client for the given bucket.

    Chooses credentials based on the bucket's `auth_mode`:
    - "role": optionally assumes the provided `role_arn` using STS
    - "static": resolves credentials via `KubernetesSecretResolver` from `secret_ref`

    Args:
        b: SQLAlchemy `Bucket` object containing configuration.

    Returns:
        A configured `boto3.client('s3')` instance.

    Raises:
        RuntimeError: If required fields are missing or secret resolution fails.
    """
    endpoint_url: Optional[str] = b.endpoint or os.getenv("MOCK_S3_ENDPOINT_URL")
    region_name: str = b.region or os.getenv("AWS_DEFAULT_REGION", "us-west-2")  # default region for localstack/minio

    if b.auth_mode == "role":
        if b.role_arn:
            sts = boto3.client("sts", endpoint_url=os.getenv("AWS_ENDPOINT_URL"))
            resp = sts.assume_role(RoleArn=b.role_arn, RoleSessionName="mock-fence-session")
            creds = resp["Credentials"]
            return boto3.client(
                "s3",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region_name,
                endpoint_url=endpoint_url,
                config=BotoConfig(signature_version="s3v4"),
            )
        # Fall back to ambient creds (instance metadata / env / localstack)
        return boto3.client("s3", region_name=region_name, endpoint_url=endpoint_url, config=BotoConfig(signature_version="s3v4"))

    if b.auth_mode == "static":
        if not b.secret_ref:
            raise RuntimeError("static auth_mode requires secret_ref")
        if KubernetesSecretResolver is None:
            raise RuntimeError("KubernetesSecretResolver not available")
        resolver = KubernetesSecretResolver(ttl_seconds=int(os.getenv("FENCE_SECRET_CACHE_TTL_SECONDS", "600")))
        secret = resolver.get(b.secret_ref, None)
        return boto3.client(
            "s3",
            aws_access_key_id=secret.get("access_key_id"),
            aws_secret_access_key=secret.get("secret_access_key"),
            aws_session_token=secret.get("session_token"),
            region_name=region_name,
            endpoint_url=endpoint_url,
            config=BotoConfig(signature_version="s3v4"),
        )

    raise RuntimeError(f"Unsupported auth_mode: {b.auth_mode}")

@bp.before_request
def before_request() -> None:
    """Attach a scoped DB session to the request context before each handler."""
    request.db = SessionLocal()

@bp.teardown_request
def teardown_request(exc: Optional[BaseException]) -> None:
    """Remove the scoped DB session after each request."""
    SessionLocal.remove()

@bp.route("/sign/download", methods=["POST"])
def sign_download() -> Dict[str, Any] | tuple[Dict[str, Any], int]:
    """Generate a presigned download URL (GET object).

    Body:
        {
          "bucket": "name",
          "key": "path/to.obj",
          "expires": 600
        }

    Returns:
        JSON response with fields: { "url", "method": "GET", "expires" }.
    """
    body: Dict[str, Any] = request.get_json(force=True) or {}
    bucket_name: Optional[str] = body.get("bucket")
    key: Optional[str] = body.get("key")
    expires: int = int(body.get("expires") or 600)
    if not bucket_name or not key:
        return {"error": "bucket and key required"}, 400

    b: Optional[Bucket] = request.db.query(Bucket).filter(Bucket.name == bucket_name, Bucket.status == "active").one_or_none()
    if not b:
        return {"error": "bucket not found or inactive"}, 404

    s3 = _make_s3_client_for_bucket(b)
    params = {"Bucket": b.name, "Key": key}
    url = s3.generate_presigned_url("get_object", Params=params, ExpiresIn=expires)
    return {"url": url, "method": "GET", "expires": expires}

@bp.route("/sign/upload", methods=["POST"])
def sign_upload() -> Dict[str, Any] | tuple[Dict[str, Any], int]:
    """Generate a presigned upload URL (single-part PUT).

    Body:
        {
          "bucket": "name",
          "key": "path/to.obj",
          "content_type": "application/octet-stream",
          "expires": 600
        }

    Returns:
        JSON response with fields: { "url", "method": "PUT", "expires", "headers": {...} }.
    """
    body: Dict[str, Any] = request.get_json(force=True) or {}
    bucket_name: Optional[str] = body.get("bucket")
    key: Optional[str] = body.get("key")
    expires: int = int(body.get("expires") or 600)
    content_type: str = body.get("content_type") or "application/octet-stream"
    if not bucket_name or not key:
        return {"error": "bucket and key required"}, 400

    b: Optional[Bucket] = request.db.query(Bucket).filter(Bucket.name == bucket_name, Bucket.status == "active").one_or_none()
    if not b:
        return {"error": "bucket not found or inactive"}, 404

    s3 = _make_s3_client_for_bucket(b)
    params = {"Bucket": b.name, "Key": key, "ContentType": content_type}
    url = s3.generate_presigned_url("put_object", Params=params, ExpiresIn=expires)
    return {"url": url, "method": "PUT", "expires": expires, "headers": {"Content-Type": content_type}}

@bp.route("/sign/multipart/init", methods=["POST"])
def multipart_init() -> Dict[str, str] | tuple[Dict[str, str], int]:
    """Initialize a multipart upload session.

    Body:
        { "bucket": "name", "key": "path/to.obj", "content_type": "application/octet-stream" }

    Returns:
        { "upload_id": "<id>", "bucket": "<name>", "key": "<key>" }
    """
    body: Dict[str, Any] = request.get_json(force=True) or {}
    bucket_name: Optional[str] = body.get("bucket")
    key: Optional[str] = body.get("key")
    content_type: str = body.get("content_type") or "application/octet-stream"
    if not bucket_name or not key:
        return {"error": "bucket and key required"}, 400

    b: Optional[Bucket] = request.db.query(Bucket).filter(Bucket.name == bucket_name, Bucket.status == "active").one_or_none()
    if not b:
        return {"error": "bucket not found or inactive"}, 404

    s3 = _make_s3_client_for_bucket(b)
    resp = s3.create_multipart_upload(Bucket=b.name, Key=key, ContentType=content_type)
    return {"upload_id": resp["UploadId"], "bucket": b.name, "key": key}

@bp.route("/sign/multipart/part", methods=["POST"])
def multipart_part() -> Dict[str, Any] | tuple[Dict[str, Any], int]:
    """Generate a presigned URL for uploading a single part (UploadPart).

    Body:
        { "bucket": "name", "key": "path/to.obj", "upload_id": "id", "part_number": 1, "expires": 600 }

    Returns:
        { "url": "https://...", "method": "PUT", "part_number": 1, "expires": 600 }
    """
    body: Dict[str, Any] = request.get_json(force=True) or {}
    bucket_name: Optional[str] = body.get("bucket")
    key: Optional[str] = body.get("key")
    upload_id: Optional[str] = body.get("upload_id")
    part_number: int = int(body.get("part_number") or 0)
    expires: int = int(body.get("expires") or 600)
    if not (bucket_name and key and upload_id and part_number):
        return {"error": "bucket, key, upload_id, part_number required"}, 400

    b: Optional[Bucket] = request.db.query(Bucket).filter(Bucket.name == bucket_name, Bucket.status == "active").one_or_none()
    if not b:
        return {"error": "bucket not found or inactive"}, 404

    s3 = _make_s3_client_for_bucket(b)
    params = {"Bucket": b.name, "Key": key, "UploadId": upload_id, "PartNumber": part_number}
    url = s3.generate_presigned_url("upload_part", Params=params, ExpiresIn=expires)
    return {"url": url, "method": "PUT", "part_number": part_number, "expires": expires}

@bp.route("/sign/multipart/complete", methods=["POST"])
def multipart_complete() -> Dict[str, Any] | tuple[Dict[str, Any], int]:
    """Complete a multipart upload by passing the list of parts and their ETags.

    Body:
        {
          "bucket": "name",
          "key": "path/to.obj",
          "upload_id": "id",
          "parts": [{"PartNumber":1,"ETag":"\"etag1\""}, ...]
        }

    Returns:
        Upstream S3 completion response (dict).
    """
    body: Dict[str, Any] = request.get_json(force=True) or {}
    bucket_name: Optional[str] = body.get("bucket")
    key: Optional[str] = body.get("key")
    upload_id: Optional[str] = body.get("upload_id")
    parts: list[dict] = body.get("parts") or []
    if not (bucket_name and key and upload_id and parts):
        return {"error": "bucket, key, upload_id, parts required"}, 400

    parts_sorted = sorted(parts, key=lambda p: int(p.get("PartNumber", 0)))
    b: Optional[Bucket] = request.db.query(Bucket).filter(Bucket.name == bucket_name, Bucket.status == "active").one_or_none()
    if not b:
        return {"error": "bucket not found or inactive"}, 404

    s3 = _make_s3_client_for_bucket(b)
    resp = s3.complete_multipart_upload(
        Bucket=b.name,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": parts_sorted}
    )
    return resp
