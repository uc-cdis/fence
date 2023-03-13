import flask

from fence.auth import require_auth_header
from fence.config import config

blueprint = flask.Blueprint("bucket_info", __name__)


@blueprint.route(
    "/region",
    methods=["GET"],
)
@require_auth_header(scope={"bucket_info"})
def get_bucket_region_info():
    S3_BUCKETS = config.get("S3_BUCKETS", {}).copy()
    GS_BUCKETS = config.get("GS_BUCKETS", {}).copy()
    result = {"S3_BUCKETS": S3_BUCKETS, "GS_BUCKETS": GS_BUCKETS}

    for cloud, buckets in result.items():
        for bucket, info in buckets.items():
            info_copy = info.copy()
            for key in info.keys():
                if key != "region":
                    del info_copy[key]
            buckets[bucket] = info_copy

    return flask.jsonify(result)
