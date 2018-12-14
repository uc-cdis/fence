import flask

from fence.auth import login_required, require_auth_header, current_token
from fence.blueprints.data.indexd import (
    BlankIndex,
    IndexedFile,
    get_signed_url_for_file,
)
from fence.errors import Forbidden, NotSupported, UnavailableError, UserError


blueprint = flask.Blueprint("data", __name__)


@blueprint.route("/<path:file_id>", methods=["DELETE"])
@require_auth_header(aud={"data"})
@login_required({"data"})
def delete_data_file(file_id):
    """
    Delete all the locations for a data file which was uploaded to bucket storage from
    indexd.

    If the data file is still at the first stage where it belongs to just the uploader
    (and isn't linked to a project), then the deleting user should match the uploader
    field on the record in indexd. Otherwise, the user must have delete permissions in
    the project.

    Args:
        file_id (str): GUID of file to delete
    """
    record = IndexedFile(file_id)
    # check auth: user must have uploaded the file (so `uploader` field on the record is
    # this user)
    uploader = record.index_document.get("uploader")
    if not uploader:
        raise Forbidden("deleting submitted records is not supported")
    if current_token["context"]["user"]["name"] != uploader:
        raise Forbidden("user is not uploader for file {}".format(file_id))
    flask.current_app.logger.info("deleting record and files for {}".format(file_id))
    record.delete_files(delete_all=True)
    return record.delete()


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
    if "file_name" not in params:
        raise UserError("missing required argument `file_name`")
    blank_index = BlankIndex(file_name=params["file_name"])
    max_ttl = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)
    expires_in = min(params.get("expires_in", max_ttl), max_ttl)
    response = {
        "guid": blank_index.guid,
        "url": blank_index.make_signed_url(params["file_name"], expires_in=expires_in),
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
