import os

from fence.resources.storage.cdis_jwt import create_session_token
from fence.config import config
from fence.sync.sync_users import UserSyncer


def test_google_login_error_handling(client):
    r = client.get("/login/google/login?code=abc")
    assert r.status_code == 400


def test_google_login_http_headers_are_less_than_4k_for_user_with_many_projects(
    app, client, monkeypatch, db_session
):
    """
    Test that when the current user has access to a large number of projects,
    the http headers of the response from a GET to /login/google/login are less
    than 4k bytes in size.
    """
    monkeypatch.setitem(config, "MOCK_GOOGLE_AUTH", True)
    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={
            "redirect": "https://localhost/user/oauth2/authorize?client_id=7f7kAS4MJraUuo77d7RWHr4mZ6bvGtuzup7hw46I&response_type=id_token&redirect_uri=https://webapp.example/fence&scope=openid+user+data+google_credentials&nonce=randomvalue"
        },
    )
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    user_projects = {
        "test": {
            f"project{x}": {
                "read",
                "read-storage",
                "update",
                "upload",
                "create",
                "write-storage",
                "delete",
            }
            for x in range(20)
        }
    }
    user_info = {
        "test": {
            "tags": {},
        }
    }
    dbGaP = os.environ.get("dbGaP") or config.get("dbGaP")
    syncer = UserSyncer(dbGaP, config["DB"], {})
    syncer.sync_to_db_and_storage_backend(user_projects, user_info, db_session)

    resp = client.get("/login/google/login")
    assert len(str(resp.headers)) < 4096
    assert resp.status_code == 302
