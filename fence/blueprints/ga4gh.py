import flask
from fence.errors import UserError

from fence.blueprints.data.indexd import (
    get_signed_url_for_file,
)

blueprint = flask.Blueprint("ga4gh", __name__)


@blueprint.route(
    "/drs/v1/objects/<path:object_id>/access",
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

    result = get_signed_url_for_file(
        "download", object_id, requested_protocol=access_id
    )
    return flask.jsonify(result)
