""" test /user endpoint and UserInfor Requests/Respons"""
import flask
import json
from fence.models import UserGoogleAccount


def test_userinfo_standard_claims_get(client, encoded_creds_jwt):

    encoded_credentials_jwt = encoded_creds_jwt['jwt']

    resp = client.get(
        '/user',
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})
    assert resp.json['sub']
    assert resp.json['name']
    assert resp.status_code == 200


def test_userinfo_standard_claims_post(client, encoded_creds_jwt):

    encoded_credentials_jwt = encoded_creds_jwt['jwt']

    resp = client.post(
        '/user',
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})
    assert resp.json['sub']
    assert resp.json['name']
    assert resp.status_code == 200

def test_userinfo_extra_claims_get(client, db_session, encoded_creds_jwt, primary_google_service_account):

    import pdb
    pdb.set_trace()

    encoded_credentials_jwt = encoded_creds_jwt['jwt']
    user_id = encoded_creds_jwt['user_id']
    data = {'claims':
                {'userinfo':
                    {'linked_google_email': None}}}
    google_account = 'some-authed-google-account@gmail.com'
    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    resp = client.get(
        '/user', data=json.dumps(data),
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    assert resp.json['sub']
    assert resp.json['name']
    assert resp.json['linked_google_email']
    assert resp.status_code == 200