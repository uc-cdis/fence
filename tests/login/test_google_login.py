def test_google_login_error_handling(client):
    r = client.get("/login/google/login?code=abc")
    assert r.status_code == 400
