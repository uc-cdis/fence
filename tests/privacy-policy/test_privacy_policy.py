def test_markdown(client):
    response = client.get("/privacy-policy", headers={"Accept": "text/markdown"})
    assert response.status_code == 200
    assert response.data.startswith("# Gen3/DCFS Privacy Policy")


def test_html(client):
    response = client.get("/privacy-policy", headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.data.startswith("<h1>Gen3/DCFS Privacy Policy</h1>")
    # also should default to HTML
    response = client.get("/privacy-policy", headers={"Accept": "*/*"})
    assert response.status_code == 200
    assert response.data.startswith("<h1>Gen3/DCFS Privacy Policy</h1>")
