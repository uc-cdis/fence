from . import utils
import jwt
import urlparse
import pytest


@pytest.mark.parametrize(
    'indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'], indirect=True)
def test_indexd_download_file(
        client, oauth_client, user_client, indexd_client, kid,
        rsa_private_key, primary_google_service_account, cloud_manager,
        google_signed_url):
    """
    Test ``GET /data/download/1``.
    """
    indexed_file_location = indexd_client['indexed_file_location']

    path = '/data/download/1'
    query_string = {'protocol': indexed_file_location}
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_download_context_claims(
            user_client.username, user_client.user_id),
        key=rsa_private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers, query_string=query_string)
    print(response.json)
    assert response.status_code == 200
    assert 'url' in response.json.keys()


@pytest.mark.parametrize(
    'indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'], indirect=True)
def test_indexd_upload_file(
        client, oauth_client, user_client, indexd_client, kid,
        rsa_private_key, primary_google_service_account, cloud_manager,
        google_signed_url):
    """
    Test ``GET /data/download/1``.
    """
    indexed_file_location = indexd_client['indexed_file_location']
    path = '/data/upload/1?protocol=' + indexed_file_location
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_upload_context_claims(
            user_client.username, user_client.user_id),
        key=rsa_private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert 'url' in response.json.keys()


@pytest.mark.parametrize(
    'indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'], indirect=True)
def test_indexd_download_file_no_protocol(
        client, oauth_client, user_client, indexd_client, kid,
        rsa_private_key, primary_google_service_account, cloud_manager,
        google_signed_url):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.authorized_download_context_claims(
            user_client.username, user_client.user_id),
        key=rsa_private_key,
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


@pytest.mark.parametrize(
    'indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'], indirect=True)
def test_indexd_unauthorized_download_file(
        client, oauth_client, unauthorized_user_client, indexd_client,
        cloud_manager, google_signed_url):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    response = client.get(path)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


@pytest.mark.parametrize(
    'indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'], indirect=True)
def test_unauthorized_indexd_download_file(
        client, oauth_client, user_client, indexd_client, kid,
        rsa_private_key, primary_google_service_account, cloud_manager,
        google_signed_url):
    """
    Test ``GET /data/download/1``.
    """
    path = '/data/download/1'
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.unauthorized_context_claims(
            user_client.username, user_client.user_id
        ),
        key=rsa_private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


@pytest.mark.parametrize(
    'indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'], indirect=True)
def test_unauthorized_indexd_upload_file(
        client, oauth_client, encoded_jwt, user_client, indexd_client, kid,
        rsa_private_key, primary_google_service_account, cloud_manager,
        google_signed_url):
    """
    Test ``GET /data/upload/1``.
    """
    path = '/data/upload/1'
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.unauthorized_context_claims(
            user_client.username, user_client.user_id
        ),
        key=rsa_private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


@pytest.mark.parametrize(
    'unauthorized_indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'],
    indirect=True)
def test_unavailable_indexd_upload_file(
        client, oauth_client, encoded_jwt, user_client,
        unauthorized_indexd_client, kid, rsa_private_key,
        primary_google_service_account, cloud_manager,
        google_signed_url):
    """
    Test ``GET /data/upload/1``.
    """
    path = '/data/upload/1'
    headers = {'Authorization': 'Bearer ' + jwt.encode(
        utils.unauthorized_context_claims(
            user_client.username, user_client.user_id),
        key=rsa_private_key,
        headers={'kid': kid},
        algorithm='RS256',
    )}
    response = client.get(path, headers=headers)
    assert response.status_code == 401
    assert 'url' not in response.json.keys()


@pytest.mark.parametrize(
    'public_indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'], indirect=True)
def test_public_object_download_file(
        client, auth_client, public_indexd_client,
        primary_google_service_account, cloud_manager,
        google_signed_url):
    """
    Test ``GET /data/upload/1``.
    """
    path = '/data/download/1'
    response = client.get(path)
    print(response.json)
    assert response.status_code == 200
    assert 'url' in response.json.keys()


@pytest.mark.parametrize(
    'public_bucket_indexd_client', ['gs', 's3', 'gs_acl', 's3_acl'],
    indirect=True)
def test_public_bucket_download_file(
        client, auth_client, public_bucket_indexd_client,
        primary_google_service_account, cloud_manager,
        google_signed_url):
    """
    Test ``GET /data/upload/1`` with public bucket
    """
    path = '/data/download/1'
    response = client.get(path)
    print(response.json)
    assert response.status_code == 200
    url = response.json['url']
    # public url without signature
    assert urlparse.urlparse(url).query == ''
