import time

import jwt
import pytest

from fence.config import config
from fence.jwt.blacklist import is_token_blacklisted
from fence.models import User
from tests import utils
from tests.utils.api_key import get_api_key
from tests.utils.oauth2 import create_basic_header_for_client


def test_oauth2_token_post_revoke(oauth_test_client):
    """
    Test the following procedure:
    - ``POST /oauth2/authorize`` successfully to obtain code
    - ``POST /oauth2/token`` successfully to obtain token
    - ``POST /oauth2/revoke`` to revoke the refresh token
    - Refresh token should no longer be usable at this point.
    """
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    oauth_test_client.token()
    oauth_test_client.revoke()
    # Try to use refresh token.
    refresh_token = oauth_test_client.token_response.refresh_token
    oauth_test_client.refresh(refresh_token, do_asserts=False)
    response = oauth_test_client.refresh_response.response
    assert response.status_code == 400


@pytest.mark.parametrize("revoker", ["user", "client"])
def test_blacklisted_token(
    client, oauth_client, encoded_jwt, encoded_jwt_refresh_token, revoker
):
    """
    Revoke a JWT and test that it registers as blacklisted.
    """
    if revoker == "user":
        headers = {
            "Authorization": f"Bearer {encoded_jwt}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
    else:  # revoke == "client"
        headers = create_basic_header_for_client(oauth_client)
    data = {"token": encoded_jwt_refresh_token}
    response = client.post("/oauth2/revoke", headers=headers, data=data)
    assert response.status_code == 200, response.data

    _, is_blacklisted = is_token_blacklisted(encoded_jwt_refresh_token)
    assert is_blacklisted


def test_revoke_invalid_token(client, oauth_client, kid, rsa_private_key):
    """
    Test that attempting to revoke an invalid token through the "/oauth2/revoke" endpoint fails and
    return a 200 (per RFC 7009).

    However, attempting to revoke an ID token (wrong token type, but not invalid!) does not return
    200.
    """
    headers = create_basic_header_for_client(oauth_client)

    # attempting to revoke an invalid token (expired token) should return 200
    expired_access_token = jwt.encode(
        {**utils.default_claims(), "exp": int(time.time()) - 1000},
        key=rsa_private_key,
        headers={
            "type": "JWT",
            "alg": "RS256",
            "kid": kid,
        },
        algorithm="RS256",
    )
    response = client.post(
        "/oauth2/revoke", headers=headers, data={"token": expired_access_token}
    )
    assert response.status_code == 200, response.text

    # attempting to revoke an invalid JWT should return 200
    response = client.post(
        "/oauth2/revoke",
        headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
        data={"token": "blah"},
    )
    assert response.status_code == 200, response.text

    # attempt to revoke a valid token that is not revocable (ID token): should fail
    id_token = jwt.encode(
        {"iat": int(time.time())}, key=rsa_private_key, algorithm="RS256"
    )
    response = client.post("/oauth2/revoke", headers=headers, data={"token": id_token})
    assert response.status_code == 400, response.text

    # checking if an invalid token is blacklisted should return 200
    response = client.post(
        "/credentials/token/blacklisted", headers={"Authorization": "bearer blah"}
    )
    assert response.status_code == 200, response.text


def test_revoke_regular_access_token(
    client, oauth_client, encoded_jwt, db_session, mock_arborist_requests
):
    """
    Test that a user or client cannot revoke a regular access token through the "/oauth2/revoke"
    endpoint, since we only support revoking task access tokens.
    """
    # create a user and check that they can access their own info using their own token
    headers = {"Authorization": f"bearer {encoded_jwt}"}
    db_session.add(User(id=utils.default_claims()["sub"], username="test-user"))
    db_session.commit()
    mock_arborist_requests()
    response = client.get("/user", headers=headers)
    assert response.status_code == 200, response.text

    # attempt to revoke the token with a client token
    response = client.post(
        "/oauth2/revoke",
        headers=create_basic_header_for_client(oauth_client),
        data={"token": encoded_jwt},
    )
    assert response.status_code == 400, response.text

    # attempt to revoke the token with the user's own token
    response = client.post("/oauth2/revoke", headers=headers)
    assert response.status_code == 400, response.text

    # the token should not be blacklisted
    response = client.post("/credentials/token/blacklisted", headers=headers)
    assert response.status_code == 200, response.text

    # the token should still be usable
    response = client.get("/user", headers={"Authorization": f"bearer {encoded_jwt}"})
    assert response.status_code == 200, response.text


def test_revoke_task_token_access_token(
    client, encoded_creds_jwt, mock_arborist_requests
):
    """
    Test that a user can revoke a task access token through the "/oauth2/revoke"
    endpoint, and that a revoked token is rejected by the API.
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

    encoded_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # obtain a task token
    response = client.post(
        f"/credentials/api/access_token?task_token=FOO",
        data={"api_key": api_key},
        headers={"Authorization": "Bearer " + str(encoded_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "access_token" in response.json
    task_token = response.json["access_token"]

    # check that the user can access their own info using their own token
    response = client.get("/user", headers={"Authorization": f"Bearer {task_token}"})
    assert response.status_code == 200, response.text

    # the token should not be blacklisted
    response = client.post(
        "/credentials/token/blacklisted",
        headers={"Authorization": f"Bearer {task_token}"},
        json={"token": task_token},
    )
    assert response.status_code == 200, response.text

    # check that the token revocation endpoint only accepts application/x-www-form-urlencoded
    response = client.post(
        "/oauth2/revoke",
        headers={
            "Authorization": f"Bearer {task_token}",
            "Content-Type": "application/json",
        },
        json={"token": task_token},
    )
    assert response.status_code == 400, response.text

    # revoke the token
    response = client.post(
        "/oauth2/revoke",
        headers={
            "Authorization": f"Bearer {task_token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"token": task_token},
    )
    assert response.status_code == 200, response.text

    # the token should be blacklisted
    response = client.post(
        "/credentials/token/blacklisted",
        headers={"Authorization": f"Bearer {task_token}"},
        json={"token": task_token},
    )
    assert response.status_code == 403, response.text

    # the token should not be usable anymore
    response = client.get("/user", headers={"Authorization": f"Bearer {task_token}"})
    assert response.status_code == 401, response.text


def test_blacklisted_expired_token(client, oauth_client, kid, rsa_private_key):
    """
    Test that blacklisted expired tokens are still detected as blacklisted
    """
    token_lifetime = 2

    # revoke an access token
    expired_access_token = jwt.encode(
        {
            **utils.default_claims(),
            "aud": [config["DEFAULT_TOKEN_AUDIENCE"], "FOO"],
            "exp": int(time.time()) + token_lifetime,
        },
        key=rsa_private_key,
        headers={
            "type": "JWT",
            "alg": "RS256",
            "kid": kid,
        },
        algorithm="RS256",
    )
    response = client.post(
        "/oauth2/revoke",
        headers=create_basic_header_for_client(oauth_client),
        data={"token": expired_access_token},
    )
    assert response.status_code == 200, response.text

    # wait for the token to expire
    time.sleep(token_lifetime + 1)

    # checking if the expired token is blacklisted should return 403
    response = client.post(
        "/credentials/token/blacklisted",
        headers={"Authorization": f"bearer {expired_access_token}"},
    )
    assert response.status_code == 403, response.text


def test_blacklisted_endpoint_anonymous(client):
    """
    Test the token blacklisting endpoints with anonymous calls
    """
    # attempt to revoke without providing a token
    response = client.post("/oauth2/revoke")
    assert response.status_code == 400, response.text

    # check if a token is blacklisted without providing a token
    response = client.post("/credentials/token/blacklisted")
    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    "revoker",
    [
        "self",
        "authorized_user",
        "unauthorized_user",
        "authorized_anon",
        "unauthorized_anon",
    ],
)
def test_revoke_token_access(
    client, encoded_creds_jwt, kid, rsa_private_key, mock_arborist_requests, revoker
):
    """
    Test that users can only revoke their own tokens, unless they have admin access in arborist
    """
    authorized = revoker.startswith("authorized_")
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
            "arborist/auth/request": {"POST": ({"auth": authorized}, 200)},
        }
    )

    encoded_jwt = encoded_creds_jwt["jwt"]
    response = get_api_key(client, encoded_jwt)
    assert response.status_code == 200, response.text
    api_key = response.json["api_key"]

    # obtain a task token
    response = client.post(
        f"/credentials/api/access_token?task_token=FOO",
        data={"api_key": api_key},
        headers={"Authorization": "Bearer " + str(encoded_jwt)},
    )
    assert response.status_code == 200, response.text
    assert "access_token" in response.json
    task_token = response.json["access_token"]

    # attempt to revoke the token
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if revoker == "self":
        headers["Authorization"] = f"bearer {task_token}"
    elif revoker.endswith("_user"):
        claims = utils.default_claims()
        claims["context"]["user"]["name"] = "non-admin-user"
        claims["sub"] = "80"
        token = jwt.encode(
            claims, key=rsa_private_key, headers={"kid": kid}, algorithm="RS256"
        )
        headers["Authorization"] = f"bearer {token}"
    response = client.post(
        "/oauth2/revoke", headers=headers, data={"token": task_token}
    )
    assert (
        response.status_code == 200 if authorized else 403
    ), f"{authorized=}; {response.status_code=}"

    # the token should be blacklisted, unless the revoker does not have access to revoke it
    response = client.post(
        "/credentials/token/blacklisted",
        headers={"Authorization": f"Bearer {task_token}"},
        json={"token": task_token},
    )
    assert (
        response.status_code == 403 if authorized else 200
    ), f"{authorized=}; {response.status_code=}"

    # the token should not be usable anymore, unless the revoker does not have access to revoke it
    response = client.get("/user", headers={"Authorization": f"Bearer {task_token}"})
    assert (
        response.status_code == 401 if authorized else 200
    ), f"{authorized=}; {response.status_code=}"
