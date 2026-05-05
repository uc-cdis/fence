from collections import defaultdict
from typing import Optional

from flask import Blueprint, request, jsonify
from pydantic import BaseModel, ValidationError
from cdislogging import get_logger

from fence.errors import UserError, Unauthorized, Forbidden, NotFound, UnavailableError
from fence.config import config

from fence.blueprints.data.indexd import (
    get_signed_url_for_file,
    BulkIndexedFiles,
    bulk_get_signed_url_for_file,
)

blueprint = Blueprint("ga4gh", __name__)
logger = get_logger(__name__)


@blueprint.route(
    "/drs/v1/objects/<path:object_id>/access/",
    defaults={"access_id": None},
    methods=["GET"],
)
@blueprint.route(
    "/drs/v1/objects/<path:object_id>/access/<path:access_id>",
    methods=["GET", "POST"],
)
def get_ga4gh_signed_url(object_id, access_id):
    if not access_id:
        raise UserError("Access ID/Protocol is required.")

    ga4gh_passports = None
    if request.method == "POST":
        ga4gh_passports = request.get_json(force=True, silent=True).get(
            config["GA4GH_DRS_POSTED_PASSPORT_FIELD"]
        )

        if ga4gh_passports and request.headers.get("Authorization"):
            raise UserError(
                "You cannot supply both GA4GH passports and a token "
                "in the Authorization header of a request."
            )

    result = get_signed_url_for_file(
        "download",
        object_id,
        requested_protocol=access_id,
        ga4gh_passports=ga4gh_passports,
        drs="True",
    )

    return jsonify(result)


class BulkObjectAccessIds(BaseModel):
    bulk_object_id: str
    bulk_access_ids: list[str]


class BulkObjectAccessRequest(BaseModel):
    passports: Optional[list[str]] = None
    bulk_object_access_ids: list[BulkObjectAccessIds]

    def map_access_to_object_ids(self):
        result = defaultdict(list)
        for item in self.bulk_object_access_ids:
            for access_id in item.bulk_access_ids:
                result[access_id].append(item.bulk_object_id)

        return result


class ResolvedDrsObject(BaseModel):
    drs_object_id: str
    drs_access_id: str
    url: str
    headers: Optional[str]


class UnresolvedDrsObject(BaseModel):
    error_code: int
    object_ids: list[str]


class BulkObjectSummary(BaseModel):
    requested: int
    resolved: int
    unresolved: int


class BulkObjectAccessResponse(BaseModel):
    summary: BulkObjectSummary
    unresolved_drs_objects: UnresolvedDrsObject
    resolved_drs_object_access_urls: ResolvedDrsObject


@blueprint.route("/drs/v1/objects/access", methods=["POST"])
def get_ga4gh_signed_urls():
    try:
        bulk_request = BulkObjectAccessRequest(
            **request.get_json(force=True, silent=True)
        )
    except ValidationError as e:
        return jsonify(e.errors()), 400

    if request.headers.get("Authorization") and bulk_request.get("passports"):
        raise Forbidden(
            "Cannot use both Authorization header and GA4GH passports"
        )  # IMPLEMENT

    # Validate bulk request size against maxBulk config
    total_requested_count = sum(
        len(ids) for ids in bulk_request.map_access_to_object_ids().values()
    )
    max_bulk_requests = config.get("MAX_BULK_DRS_REQUESTS", 100)
    if total_requested_count > max_bulk_requests:
        return (
            jsonify(
                {
                    "error_code": 413,
                    "error_description": f"Request too large: {total_requested_count} objects requested, maximum is {max_bulk_requests}",
                }
            ),
            413,
        )

    access_to_object_ids = bulk_request.map_access_to_object_ids()
    resolved_urls = []
    unresolved_by_code = defaultdict(list)

    # Get URLs for each access protocol
    for access_id, object_ids in access_to_object_ids.items():
        try:
            result = bulk_get_signed_url_for_file(
                file_ids=object_ids,
                requested_protocol=access_id,
                ga4gh_passports=bulk_request.passports,
            )

            # Process resolved URLs
            urls = result.get("urls", [])
            for url_response in urls:
                if isinstance(url_response, dict) and "url" in url_response:
                    resolved_urls.append(
                        {
                            "drs_object_id": url_response.get("drs_object_id"),
                            "drs_access_id": access_id,
                            "url": url_response.get("url"),
                            "headers": url_response.get("headers", []),
                        }
                    )

            # Process unresolved (failed) objects
            failed_objects = result.get("failed_file_ids", [])
            for failed in failed_objects:
                error_code = failed.get("error_code", 500)
                object_ids_list = failed.get("object_ids", [])
                unresolved_by_code[error_code].extend(object_ids_list)

        except UserError as e:
            # Authorization or validation errors - mark all as 403
            logger.debug(f"UserError fetching signed URLs for {access_id}: {e}")
            unresolved_by_code[403].extend(object_ids)
        except (Unauthorized, Forbidden) as e:
            # Authentication/authorization errors
            logger.debug(f"Auth error fetching signed URLs for {access_id}: {e}")
            error_code = 401 if isinstance(e, Unauthorized) else 403
            unresolved_by_code[error_code].extend(object_ids)
        except NotFound as e:
            logger.debug(f"NotFound fetching signed URLs for {access_id}: {e}")
            unresolved_by_code[404].extend(object_ids)
        except UnavailableError as e:
            logger.error(f"UnavailableError fetching signed URLs for {access_id}: {e}")
            unresolved_by_code[500].extend(object_ids)
        except Exception as e:
            logger.error(f"Unexpected error fetching signed URLs for {access_id}: {e}")
            unresolved_by_code[500].extend(object_ids)

    # Format unresolved objects response
    unresolved_drs_objects = [
        {"error_code": error_code, "object_ids": object_ids_list}
        for error_code, object_ids_list in unresolved_by_code.items()
    ]

    # Calculate summary
    total_resolved = len(resolved_urls)
    total_unresolved = sum(len(ids) for ids in unresolved_by_code.values())

    response = {
        "summary": {
            "requested": total_requested_count,
            "resolved": total_resolved,
            "unresolved": total_unresolved,
        },
        "unresolved_drs_objects": unresolved_drs_objects,
        "resolved_drs_object_access_urls": resolved_urls,
    }

    return jsonify(response), 200
