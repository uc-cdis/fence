import mock

import fence.blueprints.privacy


def test_markdown(client, monkeypatch, privacy_policy_md):
    fence.blueprints.privacy.cache.add("privacy-policy-md", privacy_policy_md)
    response = client.get("/privacy-policy", headers={"Accept": "text/markdown"})
    assert response.status_code == 200
    assert response.data.decode("utf-8") == privacy_policy_md
    fence.blueprints.privacy.cache.clear()


def test_html(client, monkeypatch, privacy_policy_html):
    response = client.get("/privacy-policy", headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.data.decode("utf-8") == privacy_policy_html
    # also should default to HTML
    response = client.get("/privacy-policy", headers={"Accept": "*/*"})
    assert response.status_code == 200
    assert response.data.decode("utf-8") == privacy_policy_html
    fence.blueprints.privacy.cache.clear()
