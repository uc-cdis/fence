import flask
from fence.config import config

blueprint = flask.Blueprint("bucket_info", __name__)


@blueprint.route(
    "/",
    methods=["GET"],
)
def get_bucket_info():
    S3_BUCKETS = config.get("S3_BUCKETS", {})
    GS_BUCKETS = config.get("GS_BUCKETS", {})
    result = {"S3_BUCKETS": S3_BUCKETS, "GS_BUCKETS": GS_BUCKETS}

    for cloud, buckets in result.items():
        for bucket, info in buckets.items():
            del info["cred"]

    return flask.jsonify(result)
