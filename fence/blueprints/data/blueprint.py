import flask

from cdislogging import get_logger
from cdispyutils.config import get_value

from fence.auth import login_required, require_auth_header, current_token, get_jwt
from fence.authz.auth import check_arborist_auth
from fence.blueprints.data.indexd import (
    BlankIndex,
    IndexedFile,
    get_signed_url_for_file,
    verify_data_upload_bucket_configuration,
)
from fence.config import config
from fence.errors import Forbidden, InternalError, UserError, Unauthorized
from fence.utils import get_valid_expiration


logger = get_logger(__name__)

blueprint = flask.Blueprint("data", __name__)


@blueprint.route("/<path:file_id>", methods=["DELETE"])
@require_auth_header(scope={"data"})
@login_required({"data"})
def delete_data_file(file_id):
    """
    Delete all the locations for a data file which was uploaded to bucket storage from
    indexd.
    If the data file has authz matching the user's permissions, delete it.
    If the data file has no authz, then the deleting user should match the uploader
    field on the record in indexd.

    Args:
        file_id (str): GUID of file to delete
    """
    record = IndexedFile(file_id)
    authz = record.index_document.get("authz")
    has_correct_authz = None
    if authz:
        logger.debug(
            "Trying to ask arborist if user can delete in fence for {}".format(authz)
        )
        has_correct_authz = flask.current_app.arborist.auth_request(
            jwt=get_jwt(), service="fence", methods="delete", resources=authz
        )

        # If authz is not empty, use *only* arborist to check if user can delete
        # Don't fall back on uploader -- this prevents users from escalating from edit to
        # delete permissions by changing the uploader field to their own username
        # (b/c users only have edit access through arborist/authz)

        if has_correct_authz:
            logger.info("Deleting record and files for {}".format(file_id))
            message, status_code = record.delete_files(delete_all=True)
            if str(status_code)[0] != "2":
                return flask.jsonify({"message": message}), status_code

            try:
                return record.delete()
            except Exception as e:
                logger.error(e)
                return (
                    flask.jsonify(
                        {"message": "There was an error deleting this index record."}
                    ),
                    500,
                )
        else:
            return (
                flask.jsonify(
                    {
                        "message": "You do not have arborist permissions to delete this file."
                    }
                ),
                403,
            )

    # If authz is empty: use uploader == user to see if user can delete.
    uploader_mismatch_error_message = "You cannot delete this file because the uploader field indicates it does not belong to you."
    uploader = record.index_document.get("uploader")
    if not uploader:
        return (
            flask.jsonify({"message": uploader_mismatch_error_message}),
            403,
        )
    if current_token["context"]["user"]["name"] != uploader:
        return (
            flask.jsonify({"message": uploader_mismatch_error_message}),
            403,
        )
    logger.info("deleting record and files for {}".format(file_id))
    message, status_code = record.delete_files(delete_all=True)
    if str(status_code)[0] != "2":
        return flask.jsonify({"message": message}), status_code

    try:
        return record.delete()
    except Exception as e:
        logger.error(e)
        return (
            flask.jsonify(
                {"message": "There was an error deleting this index record."}
            ),
            500,
        )


@blueprint.route("/upload", methods=["POST"])
@require_auth_header(scope={"data"})
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

    authorized = False
    authz_err_msg = "Auth error when attempting to get a presigned URL for upload. User must have '{}' access on '{}'."

    authz = params.get("authz")
    uploader = None

    guid = params.get("guid")

    if authz:
        # if requesting an authz field, using new authorization method which doesn't
        # rely on uploader field, so clear it out
        uploader = ""
        authorized = flask.current_app.arborist.auth_request(
            jwt=get_jwt(),
            service="fence",
            methods=["create", "write-storage"],
            resources=authz,
        )
        if not authorized:
            logger.error(authz_err_msg.format("create' and 'write-storage", authz))
    else:
        # no 'authz' was provided, so fall back on 'file_upload' logic
        authorized = flask.current_app.arborist.auth_request(
            jwt=get_jwt(),
            service="fence",
            methods=["file_upload"],
            resources=["/data_file"],
        )
        if not authorized:
            logger.error(authz_err_msg.format("file_upload", "/data_file"))

    if not authorized:
        raise Forbidden(
            "You do not have access to upload data. You either need "
            "general file uploader permissions or create and write-storage permissions "
            "on the authz resources you specified (if you specified any)."
        )

    blank_index = BlankIndex(
        file_name=params["file_name"],
        authz=authz,
        uploader=uploader,
        guid=guid,
    )
    default_expires_in = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)

    expires_in = get_valid_expiration(
        params.get("expires_in"),
        max_limit=default_expires_in,
        default=default_expires_in,
    )

    protocol = params["protocol"] if "protocol" in params else None
    bucket = params.get("bucket")
    if bucket:
        verify_data_upload_bucket_configuration(bucket)
    response = {
        "guid": blank_index.guid,
        "url": blank_index.make_signed_url(
            file_name=params["file_name"],
            protocol=protocol,
            expires_in=expires_in,
            bucket=bucket,
        ),
    }

    return flask.jsonify(response), 201


@blueprint.route("/multipart/init", methods=["POST"])
@require_auth_header(scope={"data"})
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

    guid = params.get("guid")

    blank_index = BlankIndex(file_name=params["file_name"], guid=guid)

    default_expires_in = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)
    expires_in = get_valid_expiration(
        params.get("expires_in"),
        max_limit=default_expires_in,
        default=default_expires_in,
    )

    bucket = params.get("bucket")
    if bucket:
        verify_data_upload_bucket_configuration(bucket)

    response = {
        "guid": blank_index.guid,
        "uploadId": BlankIndex.init_multipart_upload(
            blank_index.guid + "/" + params["file_name"],
            expires_in=expires_in,
            bucket=bucket,
        ),
    }
    return flask.jsonify(response), 201


@blueprint.route("/multipart/upload", methods=["POST"])
@require_auth_header(scope={"data"})
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

    default_expires_in = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)
    expires_in = get_valid_expiration(
        params.get("expires_in"),
        max_limit=default_expires_in,
        default=default_expires_in,
    )

    bucket = params.get("bucket")
    if bucket:
        verify_data_upload_bucket_configuration(bucket)

    response = {
        "presigned_url": BlankIndex.generate_aws_presigned_url_for_part(
            params["key"],
            params["uploadId"],
            params["partNumber"],
            expires_in=expires_in,
            bucket=bucket,
        )
    }
    return flask.jsonify(response), 200


@blueprint.route("/multipart/complete", methods=["POST"])
@require_auth_header(scope={"data"})
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

    default_expires_in = flask.current_app.config.get("MAX_PRESIGNED_URL_TTL", 3600)

    bucket = params.get("bucket")
    if bucket:
        verify_data_upload_bucket_configuration(bucket)

    expires_in = get_valid_expiration(
        params.get("expires_in"),
        max_limit=default_expires_in,
        default=default_expires_in,
    )

    try:
        BlankIndex.complete_multipart_upload(
            params["key"],
            params["uploadId"],
            params["parts"],
            expires_in=expires_in,
            bucket=bucket,
        ),
    except InternalError as e:
        return flask.jsonify({"message": e.message}), e.code
    return flask.jsonify({"message": "OK"}), 200


@blueprint.route("/upload/<path:file_id>", methods=["GET"])
def upload_file(file_id):
    """
    Get a presigned url to upload a file given by file_id.
    """
    file_name = flask.request.args.get("file_name")
    if not file_name:
        file_name = str(file_id).replace("/", "_")
        logger.warning(f"file_name not provided, using '{file_name}'")

    bucket = flask.request.args.get("bucket")
    if bucket:
        verify_data_upload_bucket_configuration(bucket)

    result = get_signed_url_for_file(
        "upload", file_id, file_name=file_name, bucket=bucket
    )
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


@blueprint.route(
    "/buckets",
    methods=["GET"],
)
def get_bucket_region_info():
    """
    Get bucket information from fence-config.
    Returns all the information available for the configured buckets except creds and role-arn info.
    """
    S3_BUCKETS = config.get("S3_BUCKETS", {}).copy()
    GS_BUCKETS = config.get("GS_BUCKETS", {}).copy()
    result = {"S3_BUCKETS": S3_BUCKETS, "GS_BUCKETS": GS_BUCKETS}
    for cloud, buckets in result.items():
        for bucket, info in buckets.items():
            info_copy = {}
            for key, value in info.items():
                if not (key.lower() == "role-arn" or key.lower() == "cred"):
                    info_copy[key] = value
            buckets[bucket] = info_copy

    return flask.jsonify(result)
