"""
Tests for the Audit Service integration:
- test the creation of presigned URL audit logs
- test the creation of login audit logs
- test the SQS flow

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


import boto3
import flask
import json
import jwt
import mock
import pytest
import time
from unittest.mock import ANY, MagicMock, patch

import fence
from fence.config import config
from fence.resources.audit.utils import _clean_authorization_request_url
from tests import utils
from tests.conftest import LOGIN_IDPS


def test_clean_authorization_request_url():
    """
    Test that "code" and "state" query parameters in login URLs are redacted.
    """
    redacted_url = _clean_authorization_request_url(
        "https://my-data-commons.com/login/fence/login?code=my-secret-code&state=my-secret-state&abc=my-other-param"
    )
    assert (
        redacted_url
        == "https://my-data-commons.com/login/fence/login?code=redacted&state=redacted&abc=my-other-param"
    )


@pytest.mark.parametrize("indexd_client_with_arborist", ["s3_and_gs"], indirect=True)
def test_disabled_audit(
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
    Disable all audit logs, get a presigned URL from Fence and make sure the
    logic to create audit logs did not run.
    """
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})

    protocol = "gs"
    guid = "dg.hello/abc"
    path = f"/data/download/{guid}"
    if protocol:
        path += f"?protocol={protocol}"
    resource_paths = ["/my/resource/path1", "/path2"]
    indexd_client_with_arborist(resource_paths)
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, str(user_client.user_id)
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        ).decode("utf-8")
    }

    audit_decorator_mocker = mock.patch(
        "fence.resources.audit.utils.create_audit_log_for_request",
        new_callable=mock.Mock,
    )
    with audit_decorator_mocker as audit_decorator:
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response
        assert response.json.get("url")
        audit_decorator.assert_not_called()


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
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    guid = "dg.hello/abc"
    path = f"/data/download/{guid}"
    if protocol:
        path += f"?protocol={protocol}"
    resource_paths = ["/my/resource/path1", "/path2"]
    indexd_client_with_arborist(resource_paths)
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                # cast user_id to str because that's what we get back
                # from the DB, but audit-service expects an int.
                user_client.username,
                str(user_client.user_id),
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
                "sub": user_client.user_id,  # it's an int now
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
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    protocol = "gs"
    guid = "dg.hello/abc"
    path = f"/data/download/{guid}?protocol={protocol}"
    indexd_client_with_arborist(None)
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, str(user_client.user_id)
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
        "fence.resources.audit.client.requests", new_callable=mock.Mock
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
    Disable presigned URL logs, enable login logs, get a presigned URL from
    Fence and make sure no audit log was created.
    """
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
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
    indexd_client_with_arborist(resource_paths)
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, str(user_client.user_id)
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
def test_presigned_url_log_unauthorized(client, indexd_client, db_session, monkeypatch):
    """
    If Fence does not return a presigned URL, no audit log should be created.
    """
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
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
        assert response.status_code == 401
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/presigned_url",
            json={
                "request_url": path,
                "status_code": 401,
                "username": "anonymous",
                "sub": None,
                "guid": guid,
                "resource_paths": [],
                "action": "download",
                "protocol": "s3",
            },
        )


####################
# Login audit logs #
####################


@pytest.mark.parametrize("idp", LOGIN_IDPS)
def test_login_log_login_endpoint(
    client,
    idp,
    mock_arborist_requests,
    rsa_private_key,
    db_session,  # do not remove :-) See note at top of file
    monkeypatch,
):
    """
    Test that logging in via any of the existing IDPs triggers the creation
    of a login audit log.
    """
    mock_arborist_requests()
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"login": True})

    username = "test@test"
    callback_endpoint = "login"
    idp_name = idp
    headers = {}
    get_user_id_value = {}
    jwt_string = jwt.encode({"iat": int(time.time())}, key=rsa_private_key)

    if idp == "synapse":
        get_user_id_value = {
            "fence_username": username,
            "sub": username,
            "given_name": username,
            "family_name": username,
        }
    elif idp == "orcid":
        get_user_id_value = {"orcid": username}
    elif idp == "cilogon":
        get_user_id_value = {"sub": username}
    elif idp == "shib":
        headers["persistent_id"] = username
        idp_name = "itrust"
    elif idp == "okta":
        get_user_id_value = {"okta": username}
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
        get_user_id_value = {"username": username}
        callback_endpoint = "callback"
        # these should be populated by a /login/<idp> call that we're skipping:
        flask.g.userinfo = {}
        flask.g.tokens = {
            "refresh_token": jwt_string,
            "id_token": jwt_string,
        }
        flask.g.encoded_visas = ""
    elif idp == "generic1":
        get_user_id_value = {"generic1_username": username}
    elif idp == "generic2":
        get_user_id_value = {"sub": username}

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
        path = f"/login/{idp}/{callback_endpoint}"
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


##########################
# Push audit logs to SQS #
##########################


def mock_audit_service_sqs(app):
    # the `PUSH_AUDIT_LOGS_CONFIG` config has already been loaded during
    # the app init, so monkeypatching it is not enough
    fence.config["PUSH_AUDIT_LOGS_CONFIG"] = {
        "type": "aws_sqs",
        "aws_sqs_config": {
            "sqs_url": "mocked-sqs-url",
            "region": "region",
        },
    }

    # mock the ping function so we don't try to reach the audit-service
    mock.patch(
        "fence.resources.audit.client.AuditServiceClient._ping",
        new_callable=mock.Mock,
    ).start()

    # mock the SQS
    mocked_sqs_client = MagicMock()
    patch("fence.resources.audit.client.boto3.client", mocked_sqs_client).start()
    mocked_sqs = boto3.client(
        "sqs",
        region_name=config["PUSH_AUDIT_LOGS_CONFIG"]["aws_sqs_config"]["region"],
        endpoint_url="http://localhost",
    )
    mocked_sqs.url = config["PUSH_AUDIT_LOGS_CONFIG"]["aws_sqs_config"]["sqs_url"]
    mocked_sqs_client.return_value = mocked_sqs

    # the audit-service client has already been loaded during the app
    # init, so reload it with the new config
    fence._setup_audit_service_client(app)

    return mocked_sqs


@pytest.mark.parametrize("indexd_client_with_arborist", ["s3_and_gs"], indirect=True)
def test_presigned_url_log_push_to_sqs(
    app,
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
    Get a presigned URL from Fence and make sure an audit log was pushed
    to the configured SQS.
    """
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})
    mocked_sqs = mock_audit_service_sqs(app)

    # get a presigned URL
    protocol = "gs"
    guid = "dg.hello/abc"
    path = f"/data/download/{guid}?protocol={protocol}"
    resource_paths = ["/my/resource/path1", "/path2"]
    indexd_client_with_arborist(resource_paths)
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, str(user_client.user_id)
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200, response
    assert response.json.get("url")

    expected_audit_data = {
        "request_url": path,
        "status_code": 200,
        "username": user_client.username,
        "sub": user_client.user_id,
        "guid": guid,
        "resource_paths": resource_paths,
        "action": "download",
        "protocol": protocol,
        "category": "presigned_url",
    }
    mocked_sqs.send_message.assert_called_once_with(
        MessageBody=json.dumps(expected_audit_data), QueueUrl=mocked_sqs.url
    )


def test_login_log_push_to_sqs(
    app,
    client,
    mock_arborist_requests,
    db_session,  # do not remove :-) See note at top of file
    monkeypatch,
):
    """
    Log in and make sure an audit log was pushed to the configured SQS.
    """
    mock_arborist_requests()
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"login": True})
    mocked_sqs = mock_audit_service_sqs(app)

    username = "test@test"
    mocked_get_user_id = MagicMock(return_value={"email": username})
    get_user_id_patch = patch(
        "flask.current_app.google_client.get_user_id", mocked_get_user_id
    )
    get_user_id_patch.start()

    path = "/login/google/login"
    response = client.get(path)
    assert response.status_code == 200, response
    # not checking the parameters here because we can't json.dumps "sub: ANY"
    mocked_sqs.send_message.assert_called_once()

    get_user_id_patch.stop()
