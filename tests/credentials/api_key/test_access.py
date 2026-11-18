"""
Test using an API key to generate an access token.
"""

from unittest import mock

import flask
import pytest
import random
import time

from fence.authz.auth import can_user_get_task_token
from fence.config import config
from fence.jwt.validate import validate_jwt
from tests.utils.api_key import get_api_key

TASK_TOKEN_EXPIRES_IN = config["MAX_ACCESS_TOKEN_TTL"] + 60

# margin of error for the generated token expiration
EXP_ERR_TOLERANCE = 1


def test_get_access_token(client, encoded_creds_jwt):
    """
    Test ``POST /credentials/api/access_token``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    path = "/credentials/api/access_token"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "access_token" in response.json


def test_get_access_token_with_formdata(client, encoded_creds_jwt):
    """
    Test ``POST /credentials/api/access_token``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    path = "/credentials/api/access_token"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "access_token" in response.json


@pytest.mark.parametrize("expires_in", [None, 60, TASK_TOKEN_EXPIRES_IN])
def test_get_access_token_with_expires_in(client, encoded_creds_jwt, expires_in):
    """
    Test ``POST /credentials/api/access_token`` with the `expires_in` query parameter.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    now = int(time.time())
    path = f"/credentials/api/access_token{f'?expires_in={expires_in}' if expires_in else ''}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )

    if expires_in == TASK_TOKEN_EXPIRES_IN:
        # if the expiration is larger than the configured max, the request is rejected
        assert response.status_code == 400, response.text
        assert (
            f"Requested 'expires_in' value '{expires_in}s' is greater than the max allowed '{config['MAX_ACCESS_TOKEN_TTL']}s'".replace(
                "'", "&#39;"
            )
            in response.text
        )
    else:
        assert response.status_code == 200, response.text
        assert "access_token" in response.json
        claims = validate_jwt(response.json["access_token"])

        if expires_in is None:
            # if the expiration is not specified, the token lifetime is the configured max
            expected_exp = now + config["MAX_ACCESS_TOKEN_TTL"]
        else:
            # otherwise, the token lifetime is as requested
            expected_exp = now + expires_in

        # EXP_ERR_TOLERANCE accounts for the margin of error between the test's
        # expected token expiration and the actual token's expiration time.
        assert expected_exp <= claims["exp"] <= expected_exp + EXP_ERR_TOLERANCE


@pytest.mark.parametrize(
    "expires_in",
    [None, TASK_TOKEN_EXPIRES_IN, config["MAX_TASK_TOKEN_TTL"]["FOO"] + 60],
)
def test_task_token_authorized_user(
    client,
    encoded_creds_jwt,
    mock_arborist_requests,
    expires_in,
):
    """
    Test that a task token can be generated with a longer life than a regular token, and that the
    requested expiration is applied (except for requests that request more than the max, which are
    rejected)
    """
    task_token_type = "FOO"
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # request a task token
    now = int(time.time())
    path = f"/credentials/api/access_token?task_token={task_token_type}{f'&expires_in={expires_in}' if expires_in else ''}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )

    # check that the returned token's expiration matches
    if expires_in is None:
        # not specified: defaults to MAX_TASK_TOKEN_TTL[task_token_type]
        expected_exp = now + config["MAX_TASK_TOKEN_TTL"][task_token_type]
    elif expires_in >= config["MAX_TASK_TOKEN_TTL"][task_token_type]:
        # cannot be longer than the configured MAX_TASK_TOKEN_TTL
        assert response.status_code == 400, response.text
        assert (
            f"Requested 'expires_in' value '{expires_in}s' is greater than the max allowed '{config['MAX_TASK_TOKEN_TTL'].get(task_token_type, config['MAX_ACCESS_TOKEN_TTL'])}s'".replace(
                "'", "&#39;"
            )
            in response.text
        )
        return
    else:
        # otherwise, the requested lifetime is applied
        expected_exp = now + expires_in

    assert response.status_code == 200, response.text

    # the returned access token should have the task token type as audience
    assert "access_token" in response.json
    claims = validate_jwt(response.json["access_token"], aud=task_token_type)
    assert claims["aud"] == [task_token_type]

    # EXP_ERR_TOLERANCE accounts for the margin of error between the test's
    # expected token expiration and the actual token's expiration time.
    assert expected_exp <= claims["exp"] <= expected_exp + EXP_ERR_TOLERANCE


def test_task_token_unauthorized_user(
    client, encoded_creds_jwt, mock_arborist_requests
):
    """
    Test that a task token cannot be generated by an unauthorized user
    """
    task_token_type = "FOO"
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": False}, 200)}})

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # request a task token
    path = f"/credentials/api/access_token?task_token={task_token_type}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 403, response.text
    assert (
        f"You do not have access to obtain '{task_token_type}' tokens, or you do not have access to the token lifetime you requested".replace(
            "'", "&#39;"
        )
        in response.text
    )


def test_task_token_type_not_allowed(client, encoded_creds_jwt):
    """
    Test that a task token cannot be generated if the requested task token type is not allowed
    """
    task_token_type = "NOT_IN_ALLOWED_TASK_TOKEN_TYPES"

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # request a task token
    path = f"/credentials/api/access_token?task_token={task_token_type}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 400, response.text
    assert (
        f"Invalid 'task_token' value '{task_token_type}'. Allowed task token types are: {config['ALLOWED_TASK_TOKEN_TYPES']}".replace(
            "'", "&#39;"
        )
        in response.text
    )


def test_task_token_type_not_in_max_ttl_mapping_no_exp(
    client,
    encoded_creds_jwt,
    mock_arborist_requests,
):
    """
    Test that a task token whose type does not have a configured max expiration is generated with
    the default token expiration
    """
    task_token_type = "NOT_IN_MAX_TASK_TOKEN_TTL_MAPPING"
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # request a task token
    now = int(time.time())
    path = f"/credentials/api/access_token?task_token={task_token_type}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 200, response.text

    # `expires_in` not specified: min of MAX_ACCESS_TOKEN_TTL and MAX_TASK_TOKEN_TTL
    expected_exp = now + config["MAX_ACCESS_TOKEN_TTL"]

    # the returned access token should have the task token type as audience
    assert "access_token" in response.json
    claims = validate_jwt(response.json["access_token"], aud=task_token_type)
    assert claims["aud"] == [task_token_type]

    # EXP_ERR_TOLERANCE accounts for the margin of error between the test's
    # expected token expiration and the actual token's expiration time.
    assert expected_exp <= claims["exp"] <= expected_exp + EXP_ERR_TOLERANCE


def test_task_token_type_not_in_max_ttl_mapping_exp_too_long(client, encoded_creds_jwt):
    """
    Test that a task token whose type does not have a configured max expiration cannot be generated
    with an expiration longer than the default
    """
    task_token_type = "NOT_IN_MAX_TASK_TOKEN_TTL_MAPPING"
    expires_in = TASK_TOKEN_EXPIRES_IN

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # request a task token
    path = f"/credentials/api/access_token?task_token={task_token_type}&expires_in={expires_in}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 400, response.text
    assert f"Requested 'expires_in' value '{expires_in}s' is greater than the max allowed '{config['MAX_TASK_TOKEN_TTL'].get(task_token_type, config['MAX_ACCESS_TOKEN_TTL'])}s'"


def test_get_access_token_with_almost_expired_key(
    client, encoded_creds_jwt, mock_arborist_requests
):
    """
    Test that both access tokens or task tokens cannot be generated if the provided API key would expire before the
    token does
    """
    mock_arborist_requests(
        {
            # Assuming that the user is authorized to fetch a task token
            "arborist/auth/request": {"POST": ({"auth": True}, 200)},
        }
    )

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(
        client, encoded_credentials_jwt, expires_in=60  # expires soon
    )
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # the soon-to-be-expired API key is accepted when generating tokens for a shorter lifetime than API key's lifetime
    path = f"/credentials/api/access_token?expires_in=30"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "access_token" in response.json

    # the soon-to-be-expired API key is NOT accepted when generating regular tokens
    path = f"/credentials/api/access_token"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 400, response.text
    assert (
        "Cannot issue an access token that would expire after the provided API key does. Please obtain a new API key and try again"
        in response.text
    )

    # the soon-to-be-expired API key is NOT accepted when generating task tokens
    path = f"/credentials/api/access_token?task_token=FOO&expires_in={TASK_TOKEN_EXPIRES_IN}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 400, response.text
    assert (
        "Cannot issue an access token that would expire after the provided API key does. Please obtain a new API key and try again"
        in response.text
    )


@pytest.mark.parametrize(
    ("task_token_type", "expires_in", "authorized", "expected_can_user_get_task_token"),
    [
        ("FOO", None, True, False),
        ("FOO", random.randint(1, config["MAX_TASK_TOKEN_TTL"]["FOO"]), True, True),
        ("FOO", config["MAX_TASK_TOKEN_TTL"]["FOO"], True, True),
        ("FOO", config["MAX_TASK_TOKEN_TTL"]["FOO"] + 1, True, False),
        ("TASK_TOKEN_TYPE_WITH_FIXED_EXPIRATION", None, False, False),
        ("TASK_TOKEN_TYPE_WITH_FIXED_EXPIRATION", 200, True, True),
        ("TASK_TOKEN_TYPE_WITH_FIXED_EXPIRATION", 260, False, False),
        (
            "BLANKET_ACCESS_NOT_IN_CONFIG",
            random.randint(1, config["MAX_ACCESS_TOKEN_TTL"]),
            True,
            True,
        ),
        (
            "BLANKET_ACCESS_NOT_IN_CONFIG",
            config["MAX_ACCESS_TOKEN_TTL"] + 1,
            False,
            False,
        ),
        ("WRONG_METHOD", 200, False, False),
    ],
)
def test_can_user_get_task_token(
    app,
    mock_arborist_requests,
    task_token_type,
    expires_in,
    authorized,
    expected_can_user_get_task_token,
):
    """
    Test the logic that checks a requested expiration against the user's authz response from arborist while considering the constraints of the configured max expiration for task tokens.
    """
    mock_arborist_requests(
        {
            "arborist/auth/mapping": {
                "POST": (
                    # Note: The mapping here is only for representation purposes, the actual response
                    # for authorization check is mocked by the "authorized" parameter below
                    # based on the mapping given here.
                    {
                        "/services/fence/task-token/FOO": [
                            {"service": "fence", "method": "create"}
                        ],
                        "/services/fence/task-token/TASK_TOKEN_TYPE_WITH_FIXED_EXPIRATION/200": [
                            {"service": "fence", "method": "create"}
                        ],
                        "/services/fence/task-token/BLANKET_ACCESS_NOT_IN_CONFIG": [
                            {"service": "fence", "method": "*"}
                        ],
                        "/services/fence/task-token/WRONG_METHOD/200": [
                            {"service": "fence", "method": "delete"}
                        ],
                    },
                    200,
                )
            },
            "arborist/auth/request": {"POST": ({"auth": authorized}, 200)},
        }
    )
    with app.app_context():
        assert (
            can_user_get_task_token(task_token_type, expires_in, "test-user")
            == expected_can_user_get_task_token
        )


def test_can_user_get_task_token_asks_arborist_by_username(app, mock_arborist_requests):
    """
    Test that arborist is asked about the user by username rather than by JWT. Decoding a
    fence-issued token makes arborist fetch fence's JWKS, and fence cannot serve that
    request while it is still blocked on this one.
    """
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})

    with app.app_context():
        with mock.patch.object(
            flask.current_app.arborist,
            "auth_request",
            wraps=flask.current_app.arborist.auth_request,
        ) as auth_request:
            assert can_user_get_task_token("FOO", 200, "test-user")

        auth_request.assert_called_once()
        assert auth_request.call_args.kwargs["user_id"] == "test-user"
        assert not auth_request.call_args.kwargs["jwt"]


def test_task_token_for_a_user_that_no_longer_exists(
    client, encoded_creds_jwt, mock_arborist_requests
):
    """
    Test that an api key naming a user who no longer exists is refused a task token.
    The api key still validates, but no user resolves from it, so there is no identity
    to authorize.
    """
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    with mock.patch(
        "fence.resources.storage.cdis_jwt.get_user_from_claims", return_value=None
    ):
        response = client.post(
            "/credentials/api/access_token?task_token=FOO&expires_in=200",
            data={"api_key": api_key},
            headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
        )

    assert response.status_code == 403, response.text
