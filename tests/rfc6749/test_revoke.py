import time

import jwt
import pytest

from fence.jwt.blacklist import is_token_blacklisted
from fence.models import User
from tests import utils
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


def test_blacklisted_token(client, oauth_client, encoded_jwt_refresh_token):
    """
    Revoke a JWT and test that it registers as blacklisted.
    """
    headers = create_basic_header_for_client(oauth_client)
    data = {"token": encoded_jwt_refresh_token}
    response = client.post("/oauth2/revoke", headers=headers, data=data)
    print(encoded_jwt_refresh_token)
    import jwt

    print(
        jwt.decode(
            encoded_jwt_refresh_token,
            options={"verify_signature": False},
            algorithms=["RS256"],
        )
    )
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

    # attempt to revoke an invalid token (expired token): should succeed
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
        "/oauth2/revoke",
        headers=create_basic_header_for_client(oauth_client),
        data={"token": expired_access_token},
    )
    assert response.status_code == 200, response.text

    # attempt to revoke a valid token that is not revocable (ID token): should fail
    id_token = jwt.encode(
        {"iat": int(time.time())}, key=rsa_private_key, algorithm="RS256"
    )
    response = client.post("/oauth2/revoke", headers=headers, data={"token": id_token})
    assert response.status_code == 400, response.text


def test_revoke_client_access_token(
    client, oauth_client, encoded_jwt, db_session, mock_arborist_requests
):
    """
    Test that a client can revoke an access token through the "/oauth2/revoke" endpoint, and that a
    revoked token is rejected by the API.
    """
    # create a user and check that they can access their own info using their own token
    db_session.add(User(id=utils.default_claims()["sub"], username="test-user"))
    db_session.commit()
    mock_arborist_requests()
    response = client.get("/user", headers={"Authorization": f"bearer {encoded_jwt}"})
    assert response.status_code == 200, response.text

    # revoke the token with a client token
    response = client.post(
        "/oauth2/revoke",
        headers=create_basic_header_for_client(oauth_client),
        data={"token": encoded_jwt},
    )
    assert response.status_code == 200, response.text

    # the token should not be usable anymore
    response = client.get("/user", headers={"Authorization": f"bearer {encoded_jwt}"})
    assert response.status_code == 401, response.text


@pytest.mark.parametrize("send_body", [True, False])
def test_revoke_user_access_token(
    client, encoded_jwt, db_session, mock_arborist_requests, send_body
):
    """
    Test that a user can revoke an access token through the "/credentials/token/blacklisted"
    endpoint, and that a revoked token is rejected by the API.
    """
    # create a user and check that they can access their own info using their own token
    headers = {"Authorization": f"bearer {encoded_jwt}"}
    db_session.add(User(id=utils.default_claims()["sub"], username="test-user"))
    db_session.commit()
    mock_arborist_requests()
    response = client.get("/user", headers=headers)
    assert response.status_code == 200, response.text

    # the token should not be blacklisted
    response = client.post(
        "/credentials/token/blacklisted",
        headers=headers,
        json={"token": encoded_jwt} if send_body else None,
    )
    assert response.status_code == 200, response.text

    # revoke the token with the user's own token
    response = client.post(
        "/credentials/token/revoke",
        headers=headers,
        json={"token": encoded_jwt} if send_body else None,
    )
    assert response.status_code == 200, response.text

    # the token should be blacklisted
    response = client.post(
        "/credentials/token/blacklisted",
        headers=headers,
        json={"token": encoded_jwt} if send_body else None,
    )
    assert response.status_code == 403, response.text

    # the token should not be usable anymore
    response = client.get("/user", headers=headers)
    assert response.status_code == 401, response.text
