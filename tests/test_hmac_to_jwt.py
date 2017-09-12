from cdispyutils.constants import ALGORITHM as hmac_algorithm
from flask_jwt_extended.config import config
from flask_jwt_extended.tokens import decode_jwt

def test_anonymous_request(client):
    r = client.get('/userapi')
    assert r.status_code == 401

def test_invalid_auth_type(client):
    r = client.get('/userapi', headers={'Authorization': 'Bearer abc'})
    assert r.status_code == 401

def test_invalid_auth_content(client):
    r = client.get(
        '/userapi', headers={'Authorization': hmac_algorithm + ' abc'})
    assert r.status_code == 401

def test_valid_request(client, hmac_header):
    headers = hmac_header('/userapi', 'GET')
    r = client.get('/userapi', headers=headers)
    print r.json
    access_token = r.json['access_token']
    decoded = decode_jwt(
        encoded_token=access_token,
        secret=config.decode_key,
        algorithm=config.algorithm,
        csrf=False,
        identity_claim=config.identity_claim)
    assert 'username' in decoded['identity']
    assert 'project_access' in decoded['identity']
