import jwt
import time

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
    assert is_token_blacklisted(encoded_jwt_refresh_token)


def test_revoke_invalid_token(client, oauth_client, kid, rsa_private_key):
    """
    Test that attempting to revoke an invalid token fails and return a 200 (per RFC 7009).

    However, attempting to revoke an ID token (not invalid!) does not return 200. RFC 7009 only
    says to return 200 for tokens that are already invalid and as such cannot be used, effectively
    the same result as revoking them.
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


def test_revoke_access_token(
    client, oauth_client, encoded_jwt, db_session, mock_arborist_requests
):
    """
    Test that a client can revoke an access token, and that a revoked token is rejected by the API.
    """
    db_session.add(User(id=utils.default_claims()["sub"], username="test-user"))
    db_session.commit()
    mock_arborist_requests()
    response = client.get("/user", headers={"Authorization": f"bearer {encoded_jwt}"})
    assert response.status_code == 200, response.text

    response = client.post(
        "/oauth2/revoke",
        headers=create_basic_header_for_client(oauth_client),
        data={"token": encoded_jwt},
    )
    assert response.status_code == 200, response.text

    response = client.get("/user", headers={"Authorization": f"bearer {encoded_jwt}"})
    assert response.status_code == 401, response.text
