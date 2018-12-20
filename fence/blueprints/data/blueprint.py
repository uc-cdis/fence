import flask

from fence.auth import login_required, require_auth_header, current_token
from fence.blueprints.data.indexd import (
    BlankIndex,
    IndexedFile,
    get_signed_url_for_file,
)
from fence.errors import (
    Forbidden,
    InternalError,
    NotSupported,
    UnavailableError,
    UserError,
)
from fence.rbac import check_arborist_auth


blueprint = flask.Blueprint("data", __name__)


@blueprint.record_once
def record(setup_state):
    """
    FIXME / TODO / NOTE / DISCLAIMER

    This stuff here is a huge hack due to the current limitations of the deployment
    system with arborist. This blueprint's endpoint `/data/upload`, for uploading new
    data files, requires an arborist instance to talk to, and that the arborist instance
    be set up with some certain things (the stuff below). Currently there's not really a
    better way to make sure that this stuff always exists in arborist. Once there is
    (say arborist is loading in some YAML on initialization, which would contain the
    below information), this function should be thrown out.
    """
    app = setup_state.app
    if not hasattr(app, "arborist"):
        app.logger.warn(
            "fence app not configured with arborist client; some endpoints will be"
            " permanently inaccessible on this fence instance"
        )
        return
    app.arborist.delete_policy("data_upload")
    app.arborist.delete_resource("/data_file")
    app.arborist.delete_role("file_uploader")
    role = app.arborist.create_role({
        "id": "file_uploader",
        "description": "can upload data files",
        "permissions": [
            {
                "id": "file_upload",
                "action": {"service": "fence", "method": "file_upload"},
            },
        ]
    })
    if not role:
        raise InternalError("could not set up uploader role in arborist")
    resource = app.arborist.create_resource(
        "/",
        {
            "name": "data_file",
            "description": "data files, stored in s3",
        },
    )
    if not resource:
        raise InternalError("could not set up data file resource in arborist")
    policy = app.arborist.create_policy({
        "id": "data_upload",
        "description": "upload raw data files to S3",
        "role_ids": ["file_uploader"],
        "resource_paths": ["/data_file"],
    })
    if not policy:
        raise InternalError("could not set up data upload policy in arborist")


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
