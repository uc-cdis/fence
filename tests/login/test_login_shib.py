from fence.config import config


def test_shib_redirect(client, app):
    r = client.get("/login/shib?redirect=http://localhost")
    assert r.status_code == 302


def test_shib_login(app, client):
    r = client.get("/login/shib/login", headers={config["SHIBBOLETH_HEADER"]: "test"})
    assert r.status_code == 200


def test_shib_login_redirect(app, client):
    r = client.get("/login/shib?redirect=http://localhost")
    r = client.get("/login/shib/login", headers={config["SHIBBOLETH_HEADER"]: "test"})
    assert r.status_code == 302
    assert r.headers["Location"] == "http://localhost"


def test_shib_login_fail(client):
    r = client.get("/login/shib/login")
    assert r.status_code == 401
