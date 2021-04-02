"""
Tests for the Audit Service integration:
- test the creation of presigned URL audit logs
- test the creation of login audit logs

Note 1: there is no test for the /oauth2 endpoint: the /oauth2 endpoint
should redirect the user to the /login endpoint (tested in
`test_redirect_oauth2_authorize`), and the login endpoint should
create the audit log (tested in `test_login_log_login_endpoint`). We can't
test this end-to-end flow here because we can't mock a user login properly.

Note 2: some tests need to be set up with the `db_session` fixture even if
they don't use it explicitly, because new users are created during these
tests and we need the DB session to be cleared after they run, so other
tests looking at users are not affected.
"""


import flask
import jwt
import mock
import pytest
import time
from unittest.mock import ANY, MagicMock, patch

from fence.config import config
from fence.blueprints.login import IDP_URL_MAP
from tests import utils


############################
# Presigned URL audit logs #
############################


class MockResponse(object):
    def __init__(self, data, status_code=200):
        self.data = data
        self.status_code = status_code


@pytest.mark.parametrize("indexd_client_with_arborist", ["s3_and_gs"], indirect=True)
@pytest.mark.parametrize("protocol", ["gs", None])
def test_presigned_url_log(
    protocol,
    client,
    user_client,
    mock_arborist_requests,
    indexd_client_with_arborist,
    kid,
    rsa_private_key,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    monkeypatch,
):
    """
    Get a presigned URL from Fence and make sure a call to the Audit Service
    was made to create an audit log. Test with and without a requested
    protocol.
    """
    mock_arborist_requests(
        {"arborist/auth/request": {"POST": ('{"auth": "true"}', 200)}}
    )
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    guid = "dg.hello/abc"
    path = f"/data/download/{guid}"
    if protocol:
        path += f"?protocol={protocol}"
    resource_paths = ["/my/resource/path1", "/path2"]
    indexd_client = indexd_client_with_arborist(resource_paths)
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        ).decode("utf-8")
    }

    # protocol=None should fall back to s3 (first indexed location):
    expected_protocol = protocol or "s3"

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response
        assert response.json.get("url")
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/presigned_url",
            json={
                "request_url": path,
                "status_code": 200,
                "username": user_client.username,
                "sub": user_client.user_id,
                "guid": guid,
                "resource_paths": resource_paths,
                "action": "download",
                "protocol": expected_protocol,
            },
        )


@pytest.mark.parametrize(
    "indexd_client_with_arborist", ["s3_and_gs_acl_no_authz"], indirect=True
)
def test_presigned_url_log_acl(
    client,
    user_client,
    mock_arborist_requests,
    indexd_client_with_arborist,
    kid,
    rsa_private_key,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    monkeypatch,
):
    """
    Same as `test_presigned_url_log`, but the record contains `acl` instead
    of `authz`. The ACL is ["phs000178", "phs000218"] as defined in conftest.
    """
    mock_arborist_requests(
        {"arborist/auth/request": {"POST": ('{"auth": "true"}', 200)}}
    )
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    protocol = "gs"
    guid = "dg.hello/abc"
    path = f"/data/download/{guid}?protocol={protocol}"
    indexd_client = indexd_client_with_arborist(None)
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        ).decode("utf-8")
    }

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response
        assert response.json.get("url")
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/presigned_url",
            json={
                "request_url": path,
                "status_code": 200,
                "username": user_client.username,
                "sub": user_client.user_id,
                "guid": guid,
                "resource_paths": ["phs000178", "phs000218"],
                "action": "download",
                "protocol": protocol,
            },
        )


@pytest.mark.parametrize("public_indexd_client", ["s3_and_gs"], indirect=True)
def test_presigned_url_log_public(client, public_indexd_client, monkeypatch):
    """
    Same as `test_presigned_url_log`, but with an anonymous user downloading
    public data.
    """
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    guid = "dg.hello/abc"
    path = f"/data/download/{guid}"

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path)
        assert response.status_code == 200, response
        assert response.json.get("url")
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/presigned_url",
            json={
                "request_url": path,
                "status_code": 200,
                "username": "anonymous",
                "sub": None,
                "guid": guid,
                "resource_paths": [],
                "action": "download",
                "protocol": "s3",
            },
        )


@pytest.mark.parametrize("indexd_client_with_arborist", ["s3_and_gs"], indirect=True)
def test_presigned_url_log_disabled(
    client,
    user_client,
    mock_arborist_requests,
    indexd_client_with_arborist,
    kid,
    rsa_private_key,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
    monkeypatch,
):
    """
    Disable presigned URL logs, enable login logs, get a presigned URL from Fence and make sure no audit log was created.
    """
    mock_arborist_requests(
        {"arborist/auth/request": {"POST": ('{"auth": "true"}', 200)}}
    )
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(
        config, "ENABLE_AUDIT_LOGS", {"presigned_url": False, "login": True}
    )

    protocol = "gs"
    guid = "dg.hello/abc"
    path = f"/data/download/{guid}"
    if protocol:
        path += f"?protocol={protocol}"
    resource_paths = ["/my/resource/path1", "/path2"]
    indexd_client = indexd_client_with_arborist(resource_paths)
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        ).decode("utf-8")
    }

    # protocol=None should fall back to s3 (first indexed location):
    expected_protocol = protocol or "s3"

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response
        assert response.json.get("url")
        audit_service_requests.post.assert_not_called()


@pytest.mark.parametrize("indexd_client", ["s3_and_gs"], indirect=True)
def test_presigned_url_log_failure(client, indexd_client, db_session, monkeypatch):
    """
    If Fence does not return a presigned URL, no audit log should be created.
    """
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})
    path = "/data/download/1"
    with audit_service_mocker as audit_service_requests:
        response = client.get(path)
        assert response.status_code == 401
        audit_service_requests.post.assert_not_called()


####################
# Login audit logs #
####################


@pytest.mark.parametrize("idp", list(IDP_URL_MAP.values()))
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_login_log_login_endpoint(
    mock_discovery,
    app,
    client,
    idp,
    mock_arborist_requests,
    rsa_private_key,
    db_session,
    monkeypatch,
):
    """
    Test that logging in via any of the existing IDPs triggers the creation
    of a login audit log.
    """
    mock_arborist_requests()
    audit_service_mocker = mock.patch(
        "fence.resources.audit_service_client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"login": True})

    username = "test@test"
    endpoint = "login"
    idp_name = idp
    headers = {}
    get_user_id_value = {}
    jwt_string = jwt.encode({"iat": int(time.time())}, key=rsa_private_key)

    if idp == "synapse":
        mocked_get_user_id = MagicMock()
        get_user_id_value = {
            "fence_username": username,
            "sub": username,
            "given_name": username,
            "family_name": username,
        }
    elif idp == "orcid":
        mocked_get_user_id = MagicMock()
        get_user_id_value = {"orcid": username}
    elif idp == "shib":
        headers["persistent_id"] = username
        idp_name = "itrust"
    elif idp == "fence":
        mocked_fetch_access_token = MagicMock(return_value={"id_token": jwt_string})
        patch(
            f"flask.current_app.fence_client.fetch_access_token",
            mocked_fetch_access_token,
        ).start()
        mocked_validate_jwt = MagicMock(
            return_value={"context": {"user": {"name": username}}}
        )
        patch(
            f"fence.blueprints.login.fence_login.validate_jwt", mocked_validate_jwt
        ).start()
    elif idp == "ras":
        mocked_get_user_id = MagicMock()
        get_user_id_value = {"username": username}
        endpoint = "callback"
        # these should be populated by a /login/<idp> call that we're skipping:
        flask.g.userinfo = {}
        flask.g.tokens = {
            "refresh_token": jwt_string,
            "id_token": jwt_string,
        }

    if idp in ["google", "microsoft", "okta", "synapse", "cognito"]:
        get_user_id_value["email"] = username

    get_user_id_patch = None
    if get_user_id_value:
        mocked_get_user_id = MagicMock(return_value=get_user_id_value)
        get_user_id_patch = patch(
            f"flask.current_app.{idp}_client.get_user_id", mocked_get_user_id
        )
        get_user_id_patch.start()

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        path = f"/login/{idp}/{endpoint}"
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/login",
            json={
                "request_url": path,
                "status_code": 200,
                "username": username,
                "sub": ANY,
                "idp": idp_name,
                "fence_idp": None,
                "shib_idp": None,
                "client_id": None,
            },
        )

    if get_user_id_patch:
        get_user_id_patch.stop()
