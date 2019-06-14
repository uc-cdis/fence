""" test /user endpoint and UserInfo Requests/Response"""
import json

import pytest

from fence.models import UserGoogleAccount


@pytest.fixture(autouse=True)
def mock_arborist(mock_arborist_requests):
    mock_arborist_requests()


def test_userinfo_standard_claims_get(client, encoded_creds_jwt):

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]

    resp = client.get(
        "/user", headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )
    print(resp.json)
    assert resp.json["sub"]
    assert resp.json["name"]
    assert resp.status_code == 200


def test_userinfo_standard_claims_post(client, encoded_creds_jwt):

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]

    resp = client.post(
        "/user", headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )
    assert resp.json["sub"]
    assert resp.json["name"]
    assert resp.status_code == 200


def test_userinfo_extra_claims_get(
    app, client, oauth_client, db_session, encoded_creds_jwt
):

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    db_session.add(UserGoogleAccount(user_id=user_id, email="someemail@google.com"))
    db_session.commit()
    extra_claims = {"claims": {"userinfo": {"linked_google_account": None}}}

    resp = client.post(
        "/user",
        data=json.dumps(extra_claims),
        headers={"Authorization": "Bearer " + encoded_credentials_jwt},
    )

    assert resp.json["sub"]
    assert resp.json["name"]
    assert resp.json["linked_google_account"]
    assert resp.status_code == 200
