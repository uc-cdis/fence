import json
import jwt

from fence.models import Certificate
from tests.utils import default_claims


BASE_CERT_BODY = {
    "answers": ["I agree"],
    "certificate_form": [
        {
            "name": "User agreement",
            "question": "Any unauthorized access or use of this system is prohibited and could be subject to criminal and civil penalties.",
            "options": ["I agree"],
            "answer": 0,
            "hint": "Click on I agree",
        }
    ],
}


def get_user_token(user, kid, rsa_private_key):
    claims = default_claims()
    claims["sub"] = str(user["user_id"])
    return jwt.encode(
        claims, key=rsa_private_key, headers={"kid": kid}, algorithm="RS256"
    )


def test_upload_and_download_cert(
    client, db_session, kid, rsa_private_key, test_user_a
):
    """Upload and download a cert"""
    # no existing certs in the DB
    cert_rows = db_session.query(Certificate).all()
    assert len(cert_rows) == 0

    # user uploads a cert: should create a new row in the DB
    token = get_user_token(test_user_a, kid, rsa_private_key)
    r = client.put(
        "/user/cert/quiz?extension=txt",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        json=BASE_CERT_BODY,
    )
    assert r.status_code == 201, r.text
    cert_rows = db_session.query(Certificate).all()
    assert len(cert_rows) == 1
    assert cert_rows[0].filename == "quiz.txt"
    assert json.loads(cert_rows[0].data) == BASE_CERT_BODY

    # download the cert, check that it matches the uploaded cert
    r = client.get("/user/cert/quiz", headers={"Authorization": "Bearer " + token})
    assert r.status_code == 200, r.text
    assert json.loads(r.text) == BASE_CERT_BODY


def test_upload_multiple_certs(
    client, db_session, kid, rsa_private_key, test_user_a, test_user_b
):
    """Two users upload a cert, there should be 2 rows in the DB"""
    token_user_a = get_user_token(test_user_a, kid, rsa_private_key)
    token_user_b = get_user_token(test_user_b, kid, rsa_private_key)

    # users A and B both upload a cert
    r = client.put(
        "/user/cert/quiz?extension=txt",
        headers={
            "Authorization": "Bearer " + token_user_a,
            "Content-Type": "application/json",
        },
        json=BASE_CERT_BODY,
    )
    assert r.status_code == 201, r.text
    r = client.put(
        "/user/cert/quiz?extension=txt",
        headers={
            "Authorization": "Bearer " + token_user_b,
            "Content-Type": "application/json",
        },
        json=BASE_CERT_BODY,
    )
    assert r.status_code == 201, r.text

    # there should be 2 separate rows in the DB
    cert_rows = db_session.query(Certificate).all()
    assert len(cert_rows) == 2


def test_update_existing_cert(client, db_session, kid, rsa_private_key, test_user_a):
    """Upload a cert and then update it, the DB should be updated"""
    # user uploads a cert: should create a new row in the DB
    token = get_user_token(test_user_a, kid, rsa_private_key)
    r = client.put(
        "/user/cert/quiz?extension=txt",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        json=BASE_CERT_BODY,
    )
    assert r.status_code == 201, r.text
    cert_rows = db_session.query(Certificate).all()
    assert len(cert_rows) == 1
    assert cert_rows[0].filename == "quiz.txt"
    assert json.loads(cert_rows[0].data) == BASE_CERT_BODY
    user_a_cert_id = cert_rows[0].id

    # user uploads an update to an existing cert: should NOT create a new row in the DB, and
    # should update the existing row
    new_answer = "I DO NOT agree"
    r = client.put(
        "/user/cert/quiz?extension=txt",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        json={**BASE_CERT_BODY, "answers": [new_answer]},
    )
    assert r.status_code == 201, r.text

    cert_rows = db_session.query(Certificate).filter_by(id=user_a_cert_id).all()
    assert len(cert_rows) == 1
    assert json.loads(cert_rows[0].data)["answers"] == [new_answer]
