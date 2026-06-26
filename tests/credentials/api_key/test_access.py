"""
Test using an API key to generate an access token.
"""

import pytest
import random
import time

from fence.authz.auth import can_user_get_task_token
from fence.config import config
from fence.jwt.validate import validate_jwt
from tests.utils.api_key import get_api_key

TASK_TOKEN_EXPIRES_IN = config["MAX_ACCESS_TOKEN_TTL"] + 60


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

    now = int(time.time())
    if expires_in in [None, TASK_TOKEN_EXPIRES_IN]:
        # if the expiration is not specified or larger than the configured max, the token lifetime
        # is the configured max
        expected_exp = now + config["MAX_ACCESS_TOKEN_TTL"]
    else:
        # otherwise, the token lifetime is as requested
        expected_exp = now + expires_in
    assert expected_exp == claims["exp"]


@pytest.mark.parametrize(
    ("task_token_type", "expires_in", "authorized"),
    [
        ("FOO", None, True),
        ("FOO", TASK_TOKEN_EXPIRES_IN, True),
        ("FOO", config["MAX_TASK_TOKEN_TTL"]["FOO"] + 60, True),
        ("NOT_IN_CONFIG", config["MAX_TASK_TOKEN_TTL"]["FOO"] + 60, True),
        ("NOT_IN_MAPPING", TASK_TOKEN_EXPIRES_IN, False),
    ],
)
def test_task_token(
    client,
    encoded_creds_jwt,
    mock_arborist_requests,
    expires_in,
    task_token_type,
    authorized,
):
    """
    Test that a task token can be generated with a longer life than a regular token, and that the configured max expiration is respected
    """
    mock_arborist_requests(
        {
            "arborist/auth/request": {"POST": ({"auth": authorized}, 200)},
        }
    )

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # request a task token
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
    claims = validate_jwt(response.json["access_token"], aud=task_token_type)
    assert claims["aud"] == [task_token_type]

    now = int(time.time())
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
    assert expected_exp == claims["exp"]


def test_get_access_token_with_almost_expired_key(
    client, encoded_creds_jwt, mock_arborist_requests
):
    """
    Test that task tokens cannot be generated if the provided API key would expire before the
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
    Test the logic that checks a requested expiration against the user's authz, capping the expiration to the configured max for that task token type.
    """
    mock_arborist_requests(
        {
            "arborist/auth/mapping": {
                "POST": (
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
                    },
                    200,
                )
            },
            "arborist/auth/request": {"POST": ({"auth": authorized}, 200)},
        }
    )
    with app.app_context():
        assert (
            can_user_get_task_token(task_token_type, expires_in)
            == expected_can_user_get_task_token
        )
