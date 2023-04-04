def test_get_bucket_info(client):
    """
    Test /data/buckets endpoint. Check all the buckets and their correct
    region information shows up in the api response from fence config
    """

    correct_value = {
        "S3_BUCKETS": {
            "bucket1": {},
            "bucket2": {"region": "us-east-1"},
            "bucket3": {"region": "us-east-1"},
            "bucket4": {"region": "us-east-1"},
            "bucket5": {"region": "us-east-1"},
        },
        "GS_BUCKETS": {
            "bucket1": {"region": "us-east-1"},
            "bucket2": {"region": "us-east-1"},
        },
    }

    res = client.get("/data/buckets")

    assert res.status_code == 200

    bucket_info = res.json
    for cloud, buckets in bucket_info.items():
        for bucket, info in buckets.items():
            assert "cred" not in info

    assert len(bucket_info["S3_BUCKETS"]) == 5
    assert len(bucket_info["GS_BUCKETS"]) == 2

    assert res.json == correct_value
