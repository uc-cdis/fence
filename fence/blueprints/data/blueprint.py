import flask

from fence.auth import login_required, require_auth_header
from fence.errors import (
    NotFound,
    NotSupported,
    Unauthorized,
    UnavailableError,
    UserError,
)

from fence.blueprints.data.indexd import BlankIndex, get_signed_url_for_file


blueprint = flask.Blueprint("data", __name__)


@blueprint.route("/upload", methods=["POST"])
@require_auth_header(aud={"data"})
@login_required({"data"})
def upload_data_file():
    """
    Return a presigned URL for use with uploading a data file.

    See the documentation on the entire flow here for more info:

        https://github.com/uc-cdis/cdis-wiki/tree/master/dev/gen3/data_upload

    """
    # make new record in indexd, with just the `uploader` field (and a GUID)
    params = flask.request.get_json()
    if not params:
        raise UserError("wrong Content-Type; expected application/json")
    if "filename" not in params:
        raise UserError("missing required argument `filename`")
    blank_index = BlankIndex(filename=params["filename"])
    max_ttl = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)
    expires_in = min(params.get("expires_in", max_ttl), max_ttl)
    response = {
        "guid": blank_index.guid,
        "url": blank_index.make_signed_url(params["filename"], expires_in=expires_in),
    }
    return flask.jsonify(response), 201


@blueprint.route("/upload/<path:file_id>", methods=["GET"])
def upload_file(file_id):
    """
    Get a presigned url to upload a file given by file_id.
    """
    result = get_signed_url_for_file("upload", file_id)
    return flask.jsonify(result)


@blueprint.route("/download/<path:file_id>", methods=["GET"])
def download_file(file_id):
    """
    Get a presigned url to download a file given by file_id.
    """
    result = get_signed_url_for_file("download", file_id)
    if not "redirect" in flask.request.args or not "url" in result:
        return flask.jsonify(result)
    return flask.redirect(result["url"])
