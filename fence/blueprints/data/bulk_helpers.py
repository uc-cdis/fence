from collections import defaultdict
from dataclasses import dataclass

import flask
from cdislogging import get_logger

from fence.auth import get_jwt
from fence.config import config
from fence.errors import Unauthorized, NotFound

logger = get_logger(__name__)


@dataclass
class BulkSignedUrlResult:
    """Result container for bulk signed URL generation.

    Attributes:
        signed_urls: List of resolved signed URL objects for bulk requests.
        users: List of users used to authorize each signed URL request.
        failed_guids: List of dictionaries describing failed GUIDs and error codes.
    """

    signed_urls: list
    users: list
    failed_guids: list


def normalize_authz_key(file_authz):
    """Normalize an authz entry into a canonical key.

    Args:
        file_authz: A file-level authz value, either a string or list.

    Returns:
        A normalized authz key:
        - tuple(sorted(list)) for list values
        - unchanged string values
        - None for unexpected input formats
    """
    if isinstance(file_authz, list):
        return tuple(sorted(file_authz))
    if isinstance(file_authz, str):
        return file_authz

    logger.error(f"Unexpected authz format: {file_authz}")
    return None


def collect_authz_needing_check(guids, index_document, auth_roles):
    """Collect authz keys from bulk files that need authorization verification.

    Args:
        guids: Iterable of file GUIDs requested in the bulk operation.
        index_document: Mapping of file GUID to index document metadata.
        auth_roles: List of authz keys already authorized by the request.

    Returns:
        A set of normalized authz keys that are present in the index document and
        are not already satisfied by the existing auth_roles.
    """
    authz_needing_check = set()
    for file_id in guids:
        document = index_document.get(file_id)
        if document is None:
            continue

        authz_key = normalize_authz_key(document.get("authz"))
        if authz_key is None or authz_key in auth_roles:
            continue

        authz_needing_check.add(authz_key)

    return authz_needing_check


def _auth_mapping_has_read_storage(auth_mapping, authz_key):
    """Determine whether the Arborist auth mapping grants read-storage for an authz key.

    Args:
        auth_mapping: Arborist authorization mapping for a user or token.
        authz_key: Normalized authz key from indexd metadata.

    Returns:
        True if the auth_mapping contains a fence read-storage permission for the key.
    """
    if auth_mapping is None:
        return False

    authz_list = list(authz_key) if isinstance(authz_key, tuple) else [authz_key]
    for resource in authz_list:
        methods_list = auth_mapping.get(resource)
        if not methods_list:
            continue

        if any(
            m.get("service") == "fence" and "read-storage" in m.get("method", "")
            for m in methods_list
        ):
            return True

    return False


def build_authz_to_authorized_username(authz_needing_check, users_from_passports):
    """Map requested authz keys to an authorized username where applicable.

    If passport-based users are present, this helper checks each user for the
    required read-storage permission. When no passport users exist, it falls back
    to the current request bearer token.

    Args:
        authz_needing_check: Set of authz keys requiring authorization verification.
        users_from_passports: Mapping of passport usernames to passport data.

    Returns:
        A dictionary mapping each authorized authz key to a username, or None when
        authorization is satisfied via bearer token instead of a passport user.
    """
    authz_to_authorized_username = {}
    if not authz_needing_check:
        return authz_to_authorized_username

    if users_from_passports:
        for username in users_from_passports.keys():
            try:
                auth_mapping = flask.current_app.arborist.auth_mapping(username)
            except Exception as exc:
                logger.error(f"Failed to get auth mapping for {username}: {exc}")
                continue

            for authz_key in authz_needing_check:
                if authz_key in authz_to_authorized_username:
                    continue
                if _auth_mapping_has_read_storage(auth_mapping, authz_key):
                    authz_to_authorized_username[authz_key] = username
    else:
        try:
            token = get_jwt()
        except Unauthorized:
            token = None

        try:
            auth_mapping = flask.current_app.arborist.auth_mapping(jwt=token)
        except Exception as exc:
            logger.error(f"Failed to get auth mapping from Arborist: {exc}")
            auth_mapping = {}

        for authz_key in authz_needing_check:
            if _auth_mapping_has_read_storage(auth_mapping, authz_key):
                authz_to_authorized_username[authz_key] = None

    return authz_to_authorized_username


def process_bulk_signed_urls(
    bulk,
    protocol,
    expires_in,
    force_signed_url,
    r_pays_project,
    users_from_passports,
    acl_authorization_check,
):
    """Process a bulk signed URL request and resolve per-file authorization.

    This helper holds the shared bulk request logic for indexd file
    authorization and signed URL generation. It resolves authz metadata,
    performs an Arborist check when needed, and aggregates successful signed URL
    results and failed object IDs.

    Args:
        bulk: BulkIndexedFiles instance containing guids, index_document, and auth_roles.
        protocol: Requested storage protocol for signed URLs.
        expires_in: Signed URL expiry interval.
        force_signed_url: Whether to force generation of a signed URL.
        r_pays_project: Google requestor pays project ID, if applicable.
        users_from_passports: Mapping of usernames to passport metadata.
        acl_authorization_check: Callable used for ACL-based authorization fallback.

    Returns:
        BulkSignedUrlResult containing successful signed URLs, associated users,
        and any failed GUIDs grouped by HTTP error code.
    """
    users_from_passports = users_from_passports or {}
    signed_urls = []
    users = []
    failed_guids_map = defaultdict(list)

    authz_needing_check = collect_authz_needing_check(
        bulk.guids, bulk.index_document, bulk.auth_roles
    )
    authz_to_authorized_username = build_authz_to_authorized_username(
        authz_needing_check, users_from_passports
    )

    for file_id in bulk.guids:
        if file_id not in bulk.index_document:
            failed_guids_map[404].append(file_id)
            continue

        file_authz = bulk.index_document.get(file_id).get("authz")
        authorized_user = None

        if file_authz:
            authz_key = normalize_authz_key(file_authz)
            if authz_key is None:
                failed_guids_map[500].append(file_id)
                continue

            if authz_key in bulk.auth_roles:
                if users_from_passports:
                    username = authz_to_authorized_username.get(authz_key)
                    authorized_user = users_from_passports.get(username)
                else:
                    authorized_user = None
            elif authz_key in authz_to_authorized_username:
                username = authz_to_authorized_username.get(authz_key)
                if users_from_passports:
                    authorized_user = users_from_passports.get(username)
                else:
                    authorized_user = None
                bulk.auth_roles.append(authz_key)
            else:
                error_code = 403 if users_from_passports else 401
                failed_guids_map[error_code].append(file_id)
                continue
        else:
            if not acl_authorization_check(file_id):
                failed_guids_map[401].append(file_id)
                continue

        try:
            signed_url = bulk._get_signed_urls(
                protocol,
                file_id,
                expires_in,
                force_signed_url,
                r_pays_project,
                authorized_user,
            )
            signed_urls.append({"drs_object_id": file_id, "url": signed_url})
            users.append(authorized_user)
        except Exception as exc:
            if isinstance(exc, NotFound):
                failed_guids_map[404].append(file_id)
            else:
                logger.error(
                    f"Unexpected error generating signed URL for {file_id}: {exc}"
                )
                failed_guids_map[500].append(file_id)

    failed_guids = [
        {"error_code": error_code, "object_ids": object_ids}
        for error_code, object_ids in failed_guids_map.items()
    ]

    return BulkSignedUrlResult(signed_urls, users, failed_guids)
