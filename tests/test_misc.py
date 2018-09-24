def test_healthcheck(client):
    assert client.get("/_status").status_code == 200


def test_version(client):
    r = client.get("/_version")
    assert "version" in r.json
    assert "commit" in r.json
