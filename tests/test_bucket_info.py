import fence.blueprints.bucket_info


def test_get_bucket_info(client):
    res = client.get("/bucket_info/region")

    assert res.status_code == 200

    bucket_info = res.json
    for cloud, buckets in bucket_info.items():
        for bucket, info in buckets.items():
            assert "cred" not in info

    assert len(bucket_info["S3_BUCKETS"]) == 5
    assert len(bucket_info["GS_BUCKETS"]) == 2
