from . import utils, test_settings
import jwt


def test_indexd_download_file(client, oauth_client, user_client, indexd_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1?protocol=s3'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('resources/keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_download_context_claims(user_client.username, user_client.user_id),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    print response.json
    assert response.status_code == 200
    assert 'url' in response.json.keys()


def test_indexd_upload_file(client, oauth_client, user_client, indexd_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/upload/1?protocol=s3'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('resources/keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_upload_context_claims(user_client.username, user_client.user_id),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert 'url' in response.json.keys()


def test_indexd_download_file_no_protocol(client, oauth_client, user_client, indexd_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('resources/keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_download_context_claims(user_client.username, user_client.user_id),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert 'url' in response.json.keys()


def test_indexd_download_file_no_jwt(client, auth_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    response = client.get(path)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


def test_indexd_unauthorized_download_file(client, oauth_client, unauthorized_user_client, indexd_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    response = client.get(path)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


def test_unauthorized_indexd_download_file(client, oauth_client, user_client, indexd_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('resources/keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.unauthorized_context_claims(user_client.username, user_client.user_id),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


def test_unauthorized_indexd_upload_file(client, oauth_client, encoded_jwt, user_client, indexd_client):
    """
    Test ``GET /data/upload/1``.
    """
    path = '/data/upload/1'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('resources/keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.unauthorized_context_claims(user_client.username, user_client.user_id),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


def test_unavailable_indexd_upload_file(client, oauth_client, encoded_jwt, user_client, unauthorized_indexd_client):
    """
    Test ``GET /data/upload/1``.
    """
    path = '/data/upload/1'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('resources/keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.unauthorized_context_claims(user_client.username, user_client.user_id),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


def test_public_bucket_download_file(client, auth_client, public_indexd_client):
    """
    Test ``GET /data/upload/1``.
    """
    path = '/data/download/1'
    response = client.get(path)
    print response.json
    assert response.status_code == 200
    assert 'url' in response.json.keys()
