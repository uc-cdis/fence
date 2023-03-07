from http import client
import flask
from fence.blueprints.bucket_info import get_bucket_info


def test_get_bucket_info(client):
    res = get_bucket_info()
    print(res.json)
    assert res.status_code == 200

    bucket_info = res.json
    for cloud, buckets in bucket_info.items():
        for bucket, info in buckets.items():
            assert "cred" not in bucket_info

    assert len(bucket_info["S3_BUCKETS"]) == 5
    assert len(bucket_info["GS_BUCKETS"]) == 2
