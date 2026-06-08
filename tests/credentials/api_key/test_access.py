"""
Test using an API key to generate an access token.
"""

import pytest
import time

from fence.config import config
from fence.jwt.validate import validate_jwt
from tests.utils.api_key import get_api_key


LONG_LIVED_TOKEN_EXPIRES_IN = config["MAX_ACCESS_TOKEN_TTL"] + 60

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


@pytest.mark.parametrize("expires_in", [None, 60, LONG_LIVED_TOKEN_EXPIRES_IN])
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

    if expires_in in [None, LONG_LIVED_TOKEN_EXPIRES_IN]:
        # if the expiration is not specified or larger than the configured max, the token lifetime
        # is the configured max
        expected_exp = now + config["MAX_ACCESS_TOKEN_TTL"]
    else:
        # otherwise, the token lifetime is as requested
        expected_exp = now + expires_in
    assert expected_exp <= claims["exp"] <= expected_exp + EXP_ERR_TOLERANCE


@pytest.mark.parametrize(
    "expires_in",
    [None, LONG_LIVED_TOKEN_EXPIRES_IN, config["MAX_LONG_LIVED_ACCESS_TOKEN_TTL"] + 60],
)
def test_work_order_token(client, encoded_creds_jwt, expires_in):
    """
    Test that a work order token can be generated with a longer life than a regular token

    # TODO check against configured max long-lived token exp
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_credentials_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    now = int(time.time())
    work_order_type = "BLAH"
    path = f"/credentials/api/access_token?work_order={work_order_type}{f'&expires_in={expires_in}' if expires_in else ''}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "access_token" in response.json
    claims = validate_jwt(response.json["access_token"])

    if expires_in is None:
        expected_exp = now + config["MAX_ACCESS_TOKEN_TTL"]
    elif expires_in > config["MAX_LONG_LIVED_ACCESS_TOKEN_TTL"]:
        # the expiration cannot be longer than the configured max
        expected_exp = now + config["MAX_LONG_LIVED_ACCESS_TOKEN_TTL"]
    else:
        expected_exp = now + LONG_LIVED_TOKEN_EXPIRES_IN
    assert expected_exp <= claims["exp"] <= expected_exp + EXP_ERR_TOLERANCE

    # TODO - Scopes are in the aud for backwards comp... Remove from the list once that's updated
    assert claims["aud"] == [
        config["DEFAULT_TOKEN_AUDIENCE"],
        work_order_type,
        *claims["scope"],
    ]


def test_get_access_token_with_almost_expired_key(client, encoded_creds_jwt):
    """
    Test that long-lived tokens cannot be generated if the provided API key would expire before the
    token does
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(
        client, encoded_credentials_jwt, expires_in=60  # expires soon
    )
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # the soon-to-be-expired API key is accepted when generating regular tokens
    path = f"/credentials/api/access_token?expires_in={LONG_LIVED_TOKEN_EXPIRES_IN}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "access_token" in response.json

    # the soon-to-be-expired API key is NOT accepted when generating long-lived tokens
    path = f"/credentials/api/access_token?work_order=BLAH&expires_in={LONG_LIVED_TOKEN_EXPIRES_IN}"
    data = {"api_key": api_key}
    response = client.post(
        path,
        data=data,
        headers={"Authorization": "Bearer " + str(encoded_credentials_jwt)},
    )
    assert response.status_code == 400, response.text
    assert (
        "Cannot issue a long-lived token that would expire after the provided API key does. Please obtain a new API key and try again"
        in response.text
    )
