import flask

from cdislogging import get_logger

from fence.auth import login_required, require_auth_header, current_token
from fence.blueprints.data.indexd import (
    BlankIndex,
    IndexedFile,
    get_signed_url_for_file,
)
from fence.errors import (
    Forbidden,
    InternalError,
    UserError,
)
from fence.utils import is_valid_expiration
from fence.rbac import check_arborist_auth


logger = get_logger(__name__)


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
    logger.info("deleting record and files for {}".format(file_id))
    record.delete_files(delete_all=True)
    return record.delete()


@blueprint.route("/upload", methods=["POST"])
@require_auth_header(aud={"data"})
@login_required({"data"})
@check_arborist_auth(resource="/data_file", method="file_upload")
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
    expires_in = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)
    if "expires_in" in params:
        is_valid_expiration(params["expires_in"])
        expires_in = min(params["expires_in"], expires_in)
    response = {
        "guid": blank_index.guid,
        "url": blank_index.make_signed_url(params["file_name"], expires_in=expires_in),
    }
    return flask.jsonify(response), 201


@blueprint.route("/multipart/init", methods=["POST"])
@require_auth_header(aud={"data"})
@login_required({"data"})
@check_arborist_auth(resource="/data_file", method="file_upload")
def init_multipart_upload():
    """
    Initialize a multipart upload request
    """
    params = flask.request.get_json()
    if not params:
        raise UserError("wrong Content-Type; expected application/json")
    if "file_name" not in params:
        raise UserError("missing required argument `file_name`")
    blank_index = BlankIndex(file_name=params["file_name"])
    expires_in = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)
    if "expires_in" in params:
        is_valid_expiration(params["expires_in"])
        expires_in = min(params["expires_in"], expires_in)
    response = {
        "guid": blank_index.guid,
        "uploadId": BlankIndex.init_multipart_upload(
            blank_index.guid + "/" + params["file_name"], expires_in=expires_in
        ),
    }
    return flask.jsonify(response), 201


@blueprint.route("/multipart/upload", methods=["POST"])
@require_auth_header(aud={"data"})
@login_required({"data"})
@check_arborist_auth(resource="/data_file", method="file_upload")
def generate_multipart_upload_presigned_url():
    """
    Generate multipart upload presigned url
    """
    params = flask.request.get_json()
    if not params:
        raise UserError("wrong Content-Type; expected application/json")

    missing = {"key", "uploadId", "partNumber"}.difference(set(params))
    if missing:
        raise UserError("missing required arguments: {}".format(list(missing)))

    expires_in = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)
    if "expires_in" in params:
        is_valid_expiration(params["expires_in"])
        expires_in = min(params["expires_in"], expires_in)
    response = {
        "presigned_url": BlankIndex.generate_aws_presigned_url_for_part(
            params["key"],
            params["uploadId"],
            params["partNumber"],
            expires_in=expires_in,
        )
    }
    return flask.jsonify(response), 200


@blueprint.route("/multipart/complete", methods=["POST"])
@require_auth_header(aud={"data"})
@login_required({"data"})
@check_arborist_auth(resource="/data_file", method="file_upload")
def complete_multipart_upload():
    """
    Complete multipart upload
    """
    params = flask.request.get_json()
    if not params:
        raise UserError("wrong Content-Type; expected application/json")

    missing = {"key", "uploadId", "parts"}.difference(set(params))
    if missing:
        raise UserError("missing required arguments: {}".format(list(missing)))

    expires_in = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)
    if "expires_in" in params:
        is_valid_expiration(params["expires_in"])
        expires_in = min(params["expires_in"], expires_in)

    try:
        BlankIndex.complete_multipart_upload(
            params["key"], params["uploadId"], params["parts"], expires_in=expires_in
        ),
    except InternalError as e:
        return flask.jsonify({"message": e.message}), e.code
    return flask.jsonify({"message": "OK"}), 200


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
