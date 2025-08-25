from __future__ import annotations
from flask import Blueprint, request, jsonify, current_app
from sqlalchemy.exc import IntegrityError, NoResultFound

from .models import SessionLocal, Bucket

bp = Blueprint("bucket_admin", __name__)

def require_bucket_admin() -> bool:
    """
    Mock authorization check for bucket admin actions.

    Returns:
        bool: Always True in this mock implementation.
    """
    return True

@bp.before_request
def before_request() -> None:
    """
    Attach a database session to the request context before each request.

    Returns:
        None
    """
    request.db = SessionLocal()

@bp.teardown_request
def teardown_request(exc: Exception | None) -> None:
    """
    Remove and close the database session after each request.

    Args:
        exc (Exception | None): Exception raised during request, if any.

    Returns:
        None
    """
    SessionLocal.remove()

@bp.route("/admin/buckets", methods=["GET"])
def list_buckets() -> 'flask.Response':
    """
    List all buckets.

    Returns:
        flask.Response: JSON array of bucket details.
    """
    q = request.db.query(Bucket).all()
    return jsonify([{
        "id": b.id, "name": b.name, "provider": b.provider, "region": b.region, "endpoint": b.endpoint,
        "auth_mode": b.auth_mode, "role_arn": b.role_arn, "secret_ref": bool(b.secret_ref),
        "status": b.status, "owner_project": b.owner_project
    } for b in q])

@bp.route("/admin/buckets", methods=["POST"])
def create_bucket() -> 'flask.Response':
    """
    Create a new bucket.

    Returns:
        flask.Response: JSON result or error message.
    """
    require_bucket_admin()
    data = request.get_json(force=True) or {}
    b = Bucket(**data)
    request.db.add(b)
    try:
        request.db.commit()
    except IntegrityError:
        request.db.rollback()
        return jsonify({"error": "bucket name exists"}), 409
    return jsonify({"ok": True, "name": b.name})

@bp.route("/admin/buckets/<name>", methods=["PATCH"])
def update_bucket(name: str) -> 'flask.Response':
    """
    Update an existing bucket.

    Args:
        name (str): Name of the bucket to update.

    Returns:
        flask.Response: JSON result or error message.
    """
    require_bucket_admin()
    data = request.get_json(force=True) or {}
    b = request.db.query(Bucket).filter(Bucket.name == name).one_or_none()
    if not b:
        return jsonify({"error": "not found"}), 404
    for k, v in data.items():
        if hasattr(b, k):
            setattr(b, k, v)
    request.db.commit()
    return jsonify({"ok": True})

@bp.route("/admin/buckets/<name>", methods=["DELETE"])
def delete_bucket(name: str) -> 'flask.Response':
    """
    Suspend (delete) a bucket.

    Args:
        name (str): Name of the bucket to suspend.

    Returns:
        flask.Response: JSON result or error message.
    """
    require_bucket_admin()
    b = request.db.query(Bucket).filter(Bucket.name == name).one_or_none()
    if not b:
        return jsonify({"error": "not found"}), 404
    b.status = "suspended"
    request.db.commit()
    return jsonify({"ok": True, "status": b.status})
