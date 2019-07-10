def test_markdown(client, privacy_policy_md):
    response = client.get("/privacy-policy", headers={"Accept": "text/markdown"})
    assert response.status_code == 200
    assert response.data.startswith(privacy_policy_md)


def test_html(client, privacy_policy_html):
    response = client.get("/privacy-policy", headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.data.startswith(privacy_policy_html)
    # also should default to HTML
    response = client.get("/privacy-policy", headers={"Accept": "*/*"})
    assert response.status_code == 200
    assert response.data.startswith(privacy_policy_html)
