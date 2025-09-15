"""
Tests for the metrics features (Audit Service and Prometheus)

Tests for the Audit Service integration:
- test the creation of presigned URL audit logs
- test the creation of login audit logs, with multiple audit schema model versions
- test the SQS flow

In Audit Service tests where it makes sense, we also test that Prometheus
metrics are created as expected. The last section tests Prometheus metrics
independently.

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
import boto3
import json
import jwt
import mock
import pytest
from unittest.mock import MagicMock, patch

import fence
from fence.blueprints.login import get_idp_route_name
from fence.metrics import metrics
from fence.config import config
from fence.blueprints.data.indexd import get_bucket_from_urls
from fence.models import User
from fence.resources.audit.utils import _clean_authorization_request_url
from fence.resources.audit.client import AUDIT_SCHEMA_CACHE, AuditServiceClient
from fence.errors import InternalError
from tests import utils
from tests.conftest import all_available_idps

# `reset_prometheus_metrics` must be imported even if not used so the autorun fixture gets triggered
from tests.utils.metrics import assert_prometheus_metrics, reset_prometheus_metrics


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
        )
    }

    audit_decorator_mocker = mock.patch(
        "fence.resources.audit.utils.create_audit_log_for_request",
        new_callable=mock.Mock,
    )
    with audit_decorator_mocker as audit_decorator:
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json.get("url")
        audit_decorator.assert_not_called()


############################
# Presigned URL audit logs #
############################


class MockResponse(object):
    def __init__(self, data, status_code=200):
        self.data = data
        self.status_code = status_code
        # mimic requests.Response enough for the _set_schema_models_cache code
        self._json = data
        try:
            import json as _json

            self.text = (
                _json.dumps(data) if isinstance(data, (dict, list)) else str(data)
            )
        except Exception:
            self.text = str(data)

    def json(self):
        return self._json


@pytest.mark.parametrize(
    "status_code,payload",
    [
        (200, {"login": {"version": 2.0}, "presigned_url": {"version": 1.0}}),
        (404, {}),  # fall back to default v1 schema (no error)
        (500, {}),  # should raise InternalError
    ],
)
def test_set_schema_models_cache_and_get_audit_schema(app, status_code, payload):
    """
    Unit test AuditServiceClient._set_schema_models_cache and _get_audit_schema
    for 200/404/500 responses from the audit-service /_schema endpoint.
    """
    with app.app_context():
        AUDIT_SCHEMA_CACHE.clear()
        client_obj = flask.current_app.audit_service_client

        with mock.patch(
            "fence.resources.audit.client.requests.get",
            return_value=MockResponse(payload, status_code),
        ) as get_mock:
            if status_code == 500:
                # 500 => InternalError and cache should remain empty
                with pytest.raises(InternalError):
                    client_obj._set_schema_models_cache()
                assert AUDIT_SCHEMA_CACHE.get("audit_schema") is None
                resp = client_obj._get_audit_schema()
                assert resp.status_code == 500
            else:
                # 200 or 404 should not raise
                client_obj._set_schema_models_cache()
                cached = AUDIT_SCHEMA_CACHE.get("audit_schema")
                assert cached is not None

                if status_code == 200:
                    assert cached == payload
                else:  # 404 -> default v1 schema
                    assert "login" in cached and "presigned_url" in cached
                    assert cached["login"]["version"] == 1.0
                    assert cached["presigned_url"]["version"] == 1.0
                    for k in ("request_url", "status_code", "timestamp", "username"):
                        assert k in cached["login"]["model"]
                    for k in (
                        "request_url",
                        "status_code",
                        "timestamp",
                        "username",
                        "guid",
                        "resource_paths",
                        "action",
                        "protocol",
                    ):
                        assert k in cached["presigned_url"]["model"]

                resp = client_obj._get_audit_schema()
                assert resp.status_code == status_code


@pytest.mark.parametrize("indexd_client_with_arborist", ["s3_and_gs"], indirect=True)
@pytest.mark.parametrize("endpoint", ["download", "ga4gh-drs"])
@pytest.mark.parametrize("protocol", ["gs", None])
def test_presigned_url_log(
    endpoint,
    prometheus_metrics_before,
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
    protocol. Also check that a prometheus metric is created.
    """
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    guid = "dg.hello/abc"
    if endpoint == "download":
        path = f"/data/download/{guid}"
        if protocol:
            path += f"?protocol={protocol}"
    else:
        path = f"/ga4gh/drs/v1/objects/{guid}/access/{protocol or 's3'}"
    resource_paths = ["/my/resource/path1", "/path2"]
    record = indexd_client_with_arborist(resource_paths)["record"]
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
        )
    }

    # protocol=None should fall back to s3 (first indexed location):
    expected_protocol = protocol or "s3"

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.get.return_value = MockResponse(
            {"presigned_url": {"version": 1.0}}, 200
        )
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response.text
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

    # check prometheus metrics
    resp = client.get("/metrics")
    assert resp.status_code == 200
    bucket = get_bucket_from_urls(record["urls"], expected_protocol)
    size_in_kibibytes = record["size"] / 1024
    expected_metrics = [
        {
            "name": "gen3_fence_presigned_url_total",
            "labels": {
                "action": "download",
                "authz": resource_paths,
                "bucket": bucket,
                "drs": endpoint == "ga4gh-drs",
                "protocol": expected_protocol,
                "user_sub": user_client.user_id,
            },
            "value": 1.0,
        },
        {
            "name": "gen3_fence_presigned_url_size",
            "labels": {
                "action": "download",
                "authz": resource_paths,
                "bucket": bucket,
                "drs": endpoint == "ga4gh-drs",
                "protocol": expected_protocol,
                "user_sub": user_client.user_id,
            },
            "value": size_in_kibibytes,
        },
    ]
    assert_prometheus_metrics(prometheus_metrics_before, resp.text, expected_metrics)


@pytest.mark.parametrize(
    "indexd_client_with_arborist", ["s3_and_gs_acl_no_authz"], indirect=True
)
@pytest.mark.parametrize("endpoint", ["download", "ga4gh-drs"])
def test_presigned_url_log_acl(
    endpoint,
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
    if endpoint == "download":
        path = f"/data/download/{guid}?protocol={protocol}"
    else:
        path = f"/ga4gh/drs/v1/objects/{guid}/access/{protocol}"
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
        )
    }

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response.text
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
@pytest.mark.parametrize("endpoint", ["download", "ga4gh-drs"])
def test_presigned_url_log_public(endpoint, client, public_indexd_client, monkeypatch):
    """
    Same as `test_presigned_url_log`, but with an anonymous user downloading
    public data.
    """
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    protocol = "s3"
    guid = "dg.hello/abc"
    if endpoint == "download":
        path = f"/data/download/{guid}?protocol={protocol}"
    else:
        path = f"/ga4gh/drs/v1/objects/{guid}/access/{protocol}"

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path)
        assert response.status_code == 200, response.text
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
                "protocol": protocol,
            },
        )


@pytest.mark.parametrize("indexd_client_with_arborist", ["s3_and_gs"], indirect=True)
@pytest.mark.parametrize("endpoint", ["download", "ga4gh-drs"])
def test_presigned_url_log_disabled(
    endpoint,
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
    if endpoint == "download":
        path = f"/data/download/{guid}"
    else:
        path = f"/ga4gh/drs/v1/objects/{guid}/access/{protocol}"
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
        )
    }

    with audit_service_mocker as audit_service_requests:
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        response = client.get(path, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json.get("url")
        audit_service_requests.post.assert_not_called()


@pytest.mark.parametrize("indexd_client", ["s3_and_gs"], indirect=True)
@pytest.mark.parametrize("endpoint", ["download", "ga4gh-drs"])
def test_presigned_url_log_unauthorized(
    endpoint, client, indexd_client, db_session, monkeypatch
):
    """
    If Fence does not return a presigned URL, an audit log with the appropriate status
    code should be created.
    """
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    protocol = "s3"
    guid = "dg.hello/abc"
    path = f"/data/download/{guid}?protocol={protocol}"
    if endpoint == "download":
        path = f"/data/download/{guid}?protocol={protocol}"
    else:
        path = f"/ga4gh/drs/v1/objects/{guid}/access/{protocol}"
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
                "protocol": protocol,
            },
        )


@pytest.mark.parametrize(
    "indexd_client_with_arborist", ["s3_and_gs_acl_no_authz"], indirect=True
)
@pytest.mark.parametrize("endpoint", ["download", "ga4gh-drs"])
def test_presigned_url_log_x_forwarded_headers(
    endpoint,
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
    Same as `test_presigned_url_log_acl`,but the request contains X-forwarded
    headers.
    """
    # Mock Arborist authz check
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})

    # Mock audit-service client
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
    )

    # Enable presigned_url audit logging
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"presigned_url": True})

    protocol = "gs"
    guid = "dg.hello/abc"

    # Build the request path depending on endpoint type
    if endpoint == "download":
        path = f"/data/download/{guid}?protocol={protocol}"
    else:
        path = f"/ga4gh/drs/v1/objects/{guid}/access/{protocol}"

    # Create indexd record with ACLs
    indexd_client_with_arborist(None)

    # Build Authorization header with JWT
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, str(user_client.user_id)
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        ),
        # Simulate X-Forwarded-For coming from a proxy chain
        "X-Forwarded-For": "1.2.3.4, 5.6.7.8",
    }

    with audit_service_mocker as audit_service_requests:
        AUDIT_SCHEMA_CACHE.clear()
        AUDIT_SCHEMA_CACHE.set(
            "audit_schema",
            {
                "login": {"version": 2.1},
                "presigned_url": {"version": 1.1},
            },
        )
        # Mock audit-service POST response
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )

        # Call the endpoint
        response = client.get(path, headers=headers)

        # Validate response
        assert response.status_code == 200, response.text
        assert response.json.get("url")

        # Validate audit-service log payload
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
                "additional_data": ["X-Forwarded-For:1.2.3.4, 5.6.7.8"],
            },
        )


####################
# Login audit logs #
####################


@pytest.mark.parametrize("idp", all_available_idps())
@pytest.mark.parametrize("login_schema_version", [1.0, 2.0])
def test_login_log_login_endpoint(
    client,
    idp,
    db_session,  # do not remove :-) See note at top of file
    mocks_for_idp_oauth2_callbacks,
    monkeypatch,
    prometheus_metrics_before,
    login_schema_version,
):
    """
    Test that logging in via any of the existing IDPs triggers the creation
    of a login audit log and of a prometheus metric.
    """
    audit_service_mocker = mock.patch(
        "fence.resources.audit.client.requests", new_callable=mock.Mock
    )
    monkeypatch.setitem(config, "ENABLE_AUDIT_LOGS", {"login": True})

    idp_name, username, callback_endpoint, headers = mocks_for_idp_oauth2_callbacks

    with audit_service_mocker as audit_service_requests:
        AUDIT_SCHEMA_CACHE.clear()
        AUDIT_SCHEMA_CACHE.set(
            "audit_schema",
            {
                "login": {"version": login_schema_version},
                "presigned_url": {"version": 1.0},
            },
        )
        audit_service_requests.post.return_value = MockResponse(
            data={},
            status_code=201,
        )
        path = f"/login/{get_idp_route_name(idp)}/{callback_endpoint}"
        response = client.get(path, headers=headers)
        print(f"Response: {response.status_code}, Body: {response.data}")
        assert response.status_code == 200, response.text
        user_sub = db_session.query(User).filter(User.username == username).first().id
        audit_service_requests.post.assert_called_once_with(
            "http://audit-service/log/login",
            json={
                "request_url": path,
                "status_code": 200,
                "username": username,
                "sub": user_sub,
                "idp": idp_name,
                "fence_idp": None,
                "shib_idp": None,
                "client_id": None,
                **(
                    {}
                    if login_schema_version == 1.0
                    else {
                        "ip": "flask.request.remote_addr=127.0.0.1 x_forwarded_headers=[]"
                    }
                ),
            },
        )

    # check prometheus metrics
    resp = client.get("/metrics")
    assert resp.status_code == 200
    expected_metrics = [
        {
            "name": "gen3_fence_login_total",
            "labels": {"idp": "all", "user_sub": user_sub},
            "value": 1.0,
        },
        {
            "name": "gen3_fence_login_total",
            "labels": {"idp": idp_name, "user_sub": user_sub},
            "value": 1.0,
        },
    ]
    assert_prometheus_metrics(prometheus_metrics_before, resp.text, expected_metrics)


##########################################
# Audit Service - Push audit logs to SQS #
##########################################


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
        )
    }
    response = client.get(path, headers=headers)
    assert response.status_code == 200, response.text
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
        QueueUrl=mocked_sqs.url, MessageBody=json.dumps(expected_audit_data)
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
    mocked_get_auth_info = MagicMock(return_value={"email": username})
    get_auth_info_patch = patch(
        "flask.current_app.google_client.get_auth_info", mocked_get_auth_info
    )
    get_auth_info_patch.start()

    path = "/login/google/login"
    response = client.get(path)
    assert response.status_code == 200, response.text
    # not checking the parameters here because we can't json.dumps "sub: ANY"
    mocked_sqs.send_message.assert_called_once()

    get_auth_info_patch.stop()


######################
# Prometheus metrics #
######################


def test_disabled_prometheus_metrics(client, monkeypatch):
    """
    When metrics gathering is not enabled, the metrics endpoint should not error, but it should
    not return any data.
    """
    monkeypatch.setitem(config, "ENABLE_PROMETHEUS_METRICS", False)
    metrics.add_login_event(
        user_sub="123",
        idp="test_idp",
        upstream_idp="shib",
        shib_idp="university",
        client_id="test_azp",
    )
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.text == ""


def test_record_prometheus_events(prometheus_metrics_before, client):
    """
    Validate the returned value of the metrics endpoint before any event is logged, after an event
    is logged, and after more events (one identical to the 1st one, and two different) are logged.
    """
    # NOTE: To update later. The metrics utils don't support this yet. The gauges are not handled correctly.
    # resp = client.get("/metrics")
    # assert resp.status_code == 200
    # # no metrics have been recorded yet
    # assert_prometheus_metrics(prometheus_metrics_before, resp.text, [])

    # record a login event and check that we get both a metric for the specific IDP, and an
    # IDP-agnostic metric for the total number of login events. The latter should have no IDP
    # information (no `upstream_idp` or `shib_idp`).
    metrics.add_login_event(
        user_sub="123",
        idp="test_idp",
        upstream_idp="shib",
        shib_idp="university",
        client_id="test_azp",
    )
    resp = client.get("/metrics")
    assert resp.status_code == 200
    expected_metrics = [
        {
            "name": "gen3_fence_login_total",
            "labels": {
                "user_sub": "123",
                "idp": "test_idp",
                "upstream_idp": "shib",
                "shib_idp": "university",
                "client_id": "test_azp",
            },
            "value": 1.0,
        },
        {
            "name": "gen3_fence_login_total",
            "labels": {
                "user_sub": "123",
                "idp": "all",
                "upstream_idp": "None",
                "shib_idp": "None",
                "client_id": "test_azp",
            },
            "value": 1.0,
        },
    ]
    assert_prometheus_metrics(prometheus_metrics_before, resp.text, expected_metrics)

    # same login: should increase the existing counter by 1
    metrics.add_login_event(
        user_sub="123",
        idp="test_idp",
        upstream_idp="shib",
        shib_idp="university",
        client_id="test_azp",
    )
    # login with different IDP labels: should create a new metric
    metrics.add_login_event(
        user_sub="123",
        idp="another_idp",
        upstream_idp=None,
        shib_idp=None,
        client_id="test_azp",
    )
    # new signed URL event: should create a new metric
    metrics.add_signed_url_event(
        action="upload",
        protocol="s3",
        acl=None,
        authz=["/test/path"],
        bucket="s3://test-bucket",
        user_sub="123",
        client_id="test_azp",
        drs=True,
        size_in_kibibytes=1.2,
    )
    resp = client.get("/metrics")
    assert resp.status_code == 200
    expected_metrics = [
        {
            "name": "gen3_fence_login_total",
            "labels": {
                "user_sub": "123",
                "idp": "all",
                "upstream_idp": "None",
                "shib_idp": "None",
                "client_id": "test_azp",
            },
            "value": 3.0,  # recorded login events since the beginning of the test
        },
        {
            "name": "gen3_fence_login_total",
            "labels": {
                "user_sub": "123",
                "idp": "test_idp",
                "upstream_idp": "shib",
                "shib_idp": "university",
                "client_id": "test_azp",
            },
            "value": 2.0,  # recorded login events for this idp, upstream_idp and shib_idp combo
        },
        {
            "name": "gen3_fence_login_total",
            "labels": {
                "user_sub": "123",
                "idp": "another_idp",
                "upstream_idp": "None",
                "shib_idp": "None",
                "client_id": "test_azp",
            },
            "value": 1.0,  # recorded login events for the different idp
        },
        {
            "name": "gen3_fence_presigned_url_total",
            "labels": {
                "user_sub": "123",
                "action": "upload",
                "protocol": "s3",
                "authz": ["/test/path"],
                "bucket": "s3://test-bucket",
                "user_sub": "123",
                "client_id": "test_azp",
                "drs": True,
            },
            "value": 1.0,  # recorded presigned URL events
        },
        {
            "name": "gen3_fence_presigned_url_size",
            "labels": {
                "user_sub": "123",
                "action": "upload",
                "protocol": "s3",
                "authz": ["/test/path"],
                "bucket": "s3://test-bucket",
                "user_sub": "123",
                "client_id": "test_azp",
                "drs": True,
            },
            "value": 1.2,  # presigned URL gauge with the file size as value
        },
    ]
    assert_prometheus_metrics(prometheus_metrics_before, resp.text, expected_metrics)
