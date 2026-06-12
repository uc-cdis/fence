"""
Test using an API key to generate an access token.
"""

import pytest
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
    assert response.status_code == 200, response.text
    assert "access_token" in response.json
    claims = validate_jwt(response.json["access_token"])

    if expires_in in [None, TASK_TOKEN_EXPIRES_IN]:
        # if the expiration is not specified or larger than the configured max, the token lifetime
        # is the configured max
        expected_exp = now + config["MAX_ACCESS_TOKEN_TTL"]
    else:
        # otherwise, the token lifetime is as requested
        expected_exp = now + expires_in
    assert expected_exp <= claims["exp"] <= expected_exp + EXP_ERR_TOLERANCE


@pytest.mark.parametrize(
    ("task_token_type", "expires_in"),
    [
        ("FOO", None),
        ("FOO", TASK_TOKEN_EXPIRES_IN),
        ("FOO", config["MAX_TASK_TOKEN_TTL"]["FOO"] + 60),
        ("NOT_IN_CONFIG", config["MAX_TASK_TOKEN_TTL"]["FOO"] + 60),
        ("NOT_IN_MAPPING", TASK_TOKEN_EXPIRES_IN),
    ],
)
def test_task_token(
    client, encoded_creds_jwt, mock_arborist_requests, expires_in, task_token_type
):
    """
    Test that a task token can be generated with a longer life than a regular token, and that the configured max expiration is respected
    """
    mock_arborist_requests(
        {
            "arborist/auth/mapping": {
                "POST": (
                    {
                        "/services/fence/task-token/FOO/172800": [
                            {"service": "fence", "method": "create"}
                        ],
                        "/services/fence/task-token/NOT_IN_CONFIG/172800": [
                            {"service": "*", "method": "*"}
                        ],
                    },
                    200,
                )
            },
        }
    )

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

    if task_token_type == "NOT_IN_MAPPING":
        assert response.status_code == 403, response.text
        return

    # the returned access token should have the task token type as audience
    assert response.status_code == 200, response.text
    assert "access_token" in response.json
    claims = validate_jwt(response.json["access_token"])
    assert claims["aud"] == [config["DEFAULT_TOKEN_AUDIENCE"], task_token_type]

    # check that the returned token's expiration matches
    if expires_in is None:
        # not specified: min of MAX_ACCESS_TOKEN_TTL and MAX_TASK_TOKEN_TTL
        expected_exp = now + config["MAX_ACCESS_TOKEN_TTL"]
    elif task_token_type not in config["MAX_TASK_TOKEN_TTL"]:
        # ttl not configured for this task token type: fallback to MAX_ACCESS_TOKEN_TTL
        expected_exp = now + config["MAX_ACCESS_TOKEN_TTL"]
    elif expires_in >= config["MAX_TASK_TOKEN_TTL"][task_token_type]:
        # cannot be longer than the configured MAX_TASK_TOKEN_TTL
        expected_exp = now + config["MAX_TASK_TOKEN_TTL"][task_token_type]
    else:
        # otherwise, the requested lifetime is applied
        expected_exp = now + TASK_TOKEN_EXPIRES_IN
    assert expected_exp <= claims["exp"] <= expected_exp + EXP_ERR_TOLERANCE


def test_get_access_token_with_almost_expired_key(
    client, encoded_creds_jwt, mock_arborist_requests
):
    """
    Test that task tokens cannot be generated if the provided API key would expire before the
    token does
    """
    mock_arborist_requests(
        {
            "arborist/auth/mapping": {
                "POST": (
                    {
                        "/services/fence/task-token/FOO/172800": [
                            {"service": "fence", "method": "create"}
                        ],
                    },
                    200,
                )
            },
        }
    )

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(
        client, encoded_credentials_jwt, expires_in=60  # expires soon
    )
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # the soon-to-be-expired API key is accepted when generating regular tokens
    path = f"/credentials/api/access_token?expires_in={TASK_TOKEN_EXPIRES_IN}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "access_token" in response.json

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
        "Cannot issue a task token that would expire after the provided API key does. Please obtain a new API key and try again"
        in response.text
    )


def test_can_user_get_task_token(app, mock_arborist_requests):
    """
    Test the logic that checks a requested expiration against the user's authz mapping
    """
    allowed_exp = 200
    mock_arborist_requests(
        {
            "arborist/auth/mapping": {
                "POST": (
                    {
                        f"/services/fence/task-token/FOO/{allowed_exp}": [
                            {"service": "fence", "method": "create"}
                        ],
                        "/services/fence/task-token/BLANKET_ACCESS": [
                            {"service": "fence", "method": "*"}
                        ],
                        f"/services/fence/task-token/LONG_PATH/{allowed_exp}/something": [
                            {"service": "*", "method": "create"}
                        ],
                        f"/services/fence/task-token/WRONG_METHOD/{allowed_exp}": [
                            {"service": "fence", "method": "delete"}
                        ],
                        "/services/fence/task-token/INVALID_EXP/hello": [
                            {"service": "fence", "method": "delete"}
                        ],
                    },
                    200,
                )
            },
        }
    )
    with app.app_context():
        assert can_user_get_task_token("FOO", 50) == True
        assert can_user_get_task_token("FOO", allowed_exp + 50) == False
        assert can_user_get_task_token("BLANKET_ACCESS", 50) == True
        assert can_user_get_task_token("LONG_PATH", 50) == True
        assert can_user_get_task_token("LONG_PATH", allowed_exp + 50) == False
        assert can_user_get_task_token("NOT_IN_MAPPING", 50) == False
        assert can_user_get_task_token("WRONG_METHOD", 50) == False
        assert can_user_get_task_token("INVALID_EXP", 50) == False

    mock_arborist_requests(
        {
            "arborist/auth/mapping": {
                "POST": (
                    {
                        "/services/fence/task-token": [{"service": "*", "method": "*"}],
                    },
                    200,
                )
            },
        }
    )
    with app.app_context():
        assert can_user_get_task_token("FOO", 50) == True
