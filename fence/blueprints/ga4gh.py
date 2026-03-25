from collections import defaultdict
from typing import Optional

from flask import Blueprint, request, jsonify
from pydantic import BaseModel, ValidationError

from fence.errors import UserError
from fence.config import config

from fence.blueprints.data.indexd import (
    get_signed_url_for_file,
    BulkIndexedFiles,
    bulk_get_signed_url_for_file,
)

blueprint = Blueprint("ga4gh", __name__)


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
    passports: Optional[list[str]]
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

    access_to_object_ids = bulk_request.map_access_to_object_ids()
    for access_id, object_ids in access_to_object_ids.items():
        urls = bulk_get_signed_url_for_file(
            file_ids=object_ids, requested_protocol=access_id
        )
