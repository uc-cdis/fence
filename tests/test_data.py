from . import utils, test_settings
import jwt


def test_indexd_download_file(client, oauth_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1?protocol=s3'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_download_context_claims(),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert 'url' in response.json.keys()


def test_indexd_upload_file(client, oauth_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/upload/1?protocol=s3'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_upload_context_claims(),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert 'url' in response.json.keys()


def test_indexd_download_file_no_protocol(client, oauth_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_download_context_claims(),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert 'url' in response.json.keys()


def test_unauthorized_indexd_download_file(client, oauth_client):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.unauthorized_context_claims(),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


def test_unauthorized_indexd_upload_file(client, oauth_client, encoded_jwt):
    """
    Test ``GET /data/upload/1``.
    """
    path = '/data/upload/1'
    kid = test_settings.JWT_KEYPAIR_FILES.keys()[0]
    private_key = utils.read_file('keys/test_private_key.pem')
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.unauthorized_context_claims(),
        key=private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()
