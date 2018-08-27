# pylint: disable=redefined-outer-name
"""
Define pytest fixtures.
"""

from collections import OrderedDict
from boto3 import client
import uuid
import json
import os
import copy

from addict import Dict
from authutils.testing.fixtures import (
    _hazmat_rsa_private_key,
    _hazmat_rsa_private_key_2,
    rsa_private_key,
    rsa_private_key_2,
    rsa_public_key,
    rsa_public_key_2,
)
import bcrypt
from cdisutilstest.code.storage_client_mock import get_client
import jwt
from mock import patch, MagicMock
from moto import mock_s3, mock_sts
import pytest
import requests
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.schema import DropTable

import fence
from fence import app_init
from fence import models
from fence.jwt.keys import Keypair
from fence.jwt.token import generate_signed_access_token

import tests
from tests import test_settings
from tests import utils
from tests.utils.oauth2.client import OAuth2TestClient


@compiles(DropTable, "postgresql")
def _compile_drop_table(element, compiler, **kwargs):
    return compiler.visit_drop_table(element) + " CASCADE"


# Allow authlib to use HTTP for local testing.
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


def indexd_get_available_s3_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket1/key'],
        'hashes': {},
        'metadata': {'acls': 'phs000178,phs000218'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_available_s3_bucket_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket1/key'],
        'hashes': {},
        'acl': ['phs000178', 'phs000218'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_external_s3_bucket_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket1/key'],
        'hashes': {},
        'acl': ['phs000178', 'phs000218'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_available_gs_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['gs://bucket1/key'],
        'hashes': {},
        'metadata': {'acls': 'phs000178,phs000218'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_available_gs_bucket_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['gs://bucket1/key'],
        'hashes': {},
        'acl': ['phs000178', 'phs000218'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_unavailable_s3_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket5/key'],
        'hashes': {},
        'metadata': {'acls': 'phs000178,phs000218'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_unavailable_s3_bucket_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket5/key'],
        'hashes': {},
        'acl': ['phs000178', 'phs000218'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_unavailable_gs_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['gs://bucket5/key'],
        'hashes': {},
        'metadata': {'acls': 'phs000178,phs000218'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_unavailable_gs_bucket_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['gs://bucket5/key'],
        'hashes': {},
        'acl': ['phs000178', 'phs000218'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_public_s3_object(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket1/key'],
        'hashes': {},
        'metadata': {'acls': '*'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_public_s3_object_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket1/key'],
        'hashes': {},
        'acl': ['*'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_public_gs_object(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['gs://bucket1/key'],
        'hashes': {},
        'metadata': {'acls': '*'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_public_gs_object_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['gs://bucket1/key'],
        'hashes': {},
        'acl': ['*'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_public_s3_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket4/key'],
        'hashes': {},
        'metadata': {'acls': '*'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_public_s3_bucket_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s3://bucket4/key'],
        'hashes': {},
        'acl': ['*'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_public_gs_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['gs://bucket4/key'],
        'hashes': {},
        'metadata': {'acls': '*'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_get_public_gs_bucket_acl(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['gs://bucket4/key'],
        'hashes': {},
        'acl': ['*'],
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def indexd_unsupported_protocol_bucket(file_id):
    return {
        'did': '',
        'baseid': '',
        'rev': '',
        'size': 10,
        'file_name': 'file1',
        'urls': ['s2://bucket1/key'],
        'hashes': {},
        'metadata': {'acls': 'phs000178,phs000218'},
        'form': '',
        'created_date': '',
        "updated_date": ''
    }


def mock_get_bucket_location(self, bucket, config):
    return 'us-east-1'


@mock_sts
def mock_assume_role(self, role_arn, duration_seconds, config=None):
    sts_client = client('sts', **config)
    session_name_postfix = uuid.uuid4()
    return sts_client.assume_role(
        RoleArn=role_arn, DurationSeconds=duration_seconds,
        RoleSessionName='{}-{}'.format("gen3", session_name_postfix))


@pytest.fixture(scope='session')
def claims_refresh():
    new_claims = tests.utils.default_claims()
    new_claims['pur'] = 'refresh'
    new_claims['aud'].append('fence')
    return new_claims


@pytest.fixture(scope='session')
def encoded_jwt(kid, rsa_private_key):
    """
    Return an example JWT containing the claims and encoded with the private
    key.

    Args:
        rsa_private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {'kid': kid}
    return jwt.encode(
        utils.default_claims(),
        key=rsa_private_key,
        headers=headers,
        algorithm='RS256',
    )


@pytest.fixture(scope='session')
def encoded_jwt_expired(kid, rsa_private_key):
    """
    Return an example JWT that has already expired.

    Args:
        rsa_private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {'kid': kid}
    claims_expired = utils.default_claims()
    # Move `exp` and `iat` into the past.
    claims_expired['exp'] -= 10000
    claims_expired['iat'] -= 10000
    return jwt.encode(
        claims_expired, key=rsa_private_key, headers=headers, algorithm='RS256'
    )


@pytest.fixture(scope='session')
def encoded_jwt_refresh_token(claims_refresh, kid, rsa_private_key):
    """
    Return an example JWT refresh token containing the claims and encoded with
    the private key.

    Args:
        claims_refresh (dict): fixture
        rsa_private_key (str): fixture

    Return:
        str: JWT refresh token containing claims encoded with private key
    """
    headers = {'kid': kid}
    return jwt.encode(
        claims_refresh, key=rsa_private_key, headers=headers, algorithm='RS256'
    )


class Mocker(object):

    def mock_functions(self):
        self.patcher = patch(
            'fence.resources.storage.get_client',
            get_client
        )
        self.auth_patcher = patch(
            'fence.resources.storage.StorageManager.check_auth',
            lambda cls, backend, user: True
        )
        self.boto_patcher = patch(
            'fence.resources.aws.boto_manager.BotoManager.get_bucket_region',
            mock_get_bucket_location
        )
        self.assume_role_patcher = patch(
            'fence.resources.aws.boto_manager.BotoManager.assume_role',
            mock_assume_role
        )
        self.patcher.start()
        self.auth_patcher.start()
        self.boto_patcher.start()
        self.assume_role_patcher.start()
        self.additional_patchers = []

    def unmock_functions(self):
        self.patcher.stop()
        self.auth_patcher.stop()
        self.boto_patcher.stop()
        self.assume_role_patcher.stop()
        for patcher in self.additional_patchers:
            patcher.stop()

    def add_mock(self, patcher):
        patcher.start()
        self.additional_patchers.append(patcher)


@pytest.fixture(scope='session')
def kid():
    """Return a JWT key ID to use for tests."""
    return 'test-keypair'


@pytest.fixture(scope='session')
def kid_2():
    """Return a second JWT key ID to use for tests."""
    return 'test-keypair-2'


@pytest.fixture(scope='session')
def app(kid, rsa_private_key, rsa_public_key):
    """
    Flask application fixture.
    """
    mocker = Mocker()
    mocker.mock_functions()
    root_dir = os.path.dirname(os.path.realpath(__file__))
    app_init(fence.app, test_settings, root_dir=root_dir)
    fence.app.config['TESTING'] = True
    fence.app.config['DEBUG'] = True
    # We want to set up the keys so that the test application can load keys
    # from the test keys directory, but the default keypair used will be the
    # one using the fixtures. So, stick the keypair at the front of the
    # keypairs list and reverse the ordered dictionary of public keys after
    # inserting the fixture keypair.
    fixture_keypair = Keypair(
        kid=kid, public_key=rsa_public_key, private_key=rsa_private_key
    )
    fence.app.keypairs = [fixture_keypair] + fence.app.keypairs
    fence.app.jwt_public_keys[fence.app.config['BASE_URL']][kid] = rsa_public_key
    fence.app.jwt_public_keys[fence.app.config['BASE_URL']] = OrderedDict(
        reversed(list(
            fence.app.jwt_public_keys[fence.app.config['BASE_URL']].items()
        ))
    )

    return fence.app


@pytest.fixture(scope='function')
def auth_client(app, request):
    """
    Flask application fixture.
    """
    app.config['MOCK_AUTH'] = False

    def reset_authmock():
        app.config['MOCK_AUTH'] = True

    request.addfinalizer(reset_authmock)


@pytest.fixture(scope='function')
def test_user_a(db_session):
    test_user = (
        db_session
        .query(models.User)
        .filter_by(username='test_a')
        .first()
    )
    if not test_user:
        test_user = models.User(username='test_a', is_admin=False)
        db_session.add(test_user)
        db_session.commit()
    return Dict(username='test_a', user_id=test_user.id)


@pytest.fixture(scope='function')
def test_user_b(db_session):
    test_user = (
        db_session
        .query(models.User)
        .filter_by(username='test_b')
        .first()
    )
    if not test_user:
        test_user = models.User(username='test_b', is_admin=False)
        db_session.add(test_user)
        db_session.commit()
    return Dict(username='test_b', user_id=test_user.id)


@pytest.fixture(scope='session')
def db(app, request):
    """
    Define pytest fixture for database engine (session-scoped).

    When the tests are over, drop everything from the test database.
    """

    def drop_all():
        models.Base.metadata.drop_all(app.db.engine)

    request.addfinalizer(drop_all)

    return app.db


@fence.app.route('/protected')
@fence.auth.login_required({'access'})
def protected_endpoint(methods=['GET']):
    """
    Add a protected endpoint to the app for testing.
    """
    return 'Got to protected endpoint'


@pytest.fixture(scope='function')
def user_client(db_session):
    users = dict(json.loads(
        utils.read_file('resources/authorized_users.json')
    ))
    user_id, username = utils.create_user(users, db_session, is_admin=True)
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope='function')
def unauthorized_user_client(db_session):
    users = dict(json.loads(
        utils.read_file('resources/unauthorized_users.json')
    ))
    user_id, username = utils.create_user(users, db_session, is_admin=True)
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope='function')
def awg_users(db_session):
    awg_usr = dict(json.loads(
        utils.read_file('resources/awg_user.json')
    ))
    user_id, username = utils.create_awg_user(awg_usr, db_session)


@pytest.fixture(scope='function')
def providers(db_session, app):
    providers = dict(json.loads(
        utils.read_file('resources/providers.json')
    ))
    utils.create_providers(providers, db_session)


@pytest.fixture(scope='function')
def awg_groups(db_session):
    awg_grps = dict(json.loads(
        utils.read_file('resources/awg_groups.json')
    ))
    utils.create_awg_groups(awg_grps, db_session)


@pytest.fixture(scope='function')
def db_session(db, patch_app_db_session):
    """
    Define fixture for database session (function-scoped).

    At the end of the function, roll back the session to its initial state.
    """
    connection = db.engine.connect()
    transaction = connection.begin()
    session = db.Session(bind=connection)

    patch_app_db_session(session)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope='function')
def oauth_user(app, db_session):
    users = dict(json.loads(utils.read_file(
        'resources/authorized_users.json'
    )))
    user_id, username = utils.create_user(
        users, db_session, is_admin=True
    )
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope='function')
def unauthorized_oauth_user(app, db_session):
    users = dict(json.loads(utils.read_file(
        'resources/unauthorized_users.json'
    )))
    user_id, username = utils.create_user(
        users, db_session, is_admin=True
    )
    return Dict(username=username, user_id=user_id)


@pytest.fixture(scope='function')
def indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()

    if request.param == 'gs':
        indexd_get_available_bucket_func = indexd_get_available_gs_bucket
    elif request.param == 'gs_acl':
        indexd_get_available_bucket_func = (
            indexd_get_available_gs_bucket_acl
        )
    elif request.param == 's3_acl':
        indexd_get_available_bucket_func = (
            indexd_get_available_s3_bucket_acl
        )
    elif request.param == 's3_external':
        indexd_get_available_bucket_func = (
            indexd_get_external_s3_bucket_acl
        )
    else:
        indexd_get_available_bucket_func = indexd_get_available_s3_bucket

    indexd_patcher = patch(
        'fence.blueprints.data.IndexedFile._get_index_document',
        indexd_get_available_bucket_func
    )
    mocker.add_mock(indexd_patcher)

    output = {
        'mocker': mocker,
        # only gs or s3 for location, ignore specifiers after the _
        'indexed_file_location': request.param.split('_')[0]
    }

    return output


@pytest.fixture(scope='function')
def unauthorized_indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()

    if request.param == 'gs':
        indexd_get_unavailable_bucket_func = indexd_get_unavailable_gs_bucket
    elif request.param == 'gs_acl':
        indexd_get_unavailable_bucket_func = (
            indexd_get_unavailable_gs_bucket_acl
        )
    elif request.param == 's3_acl':
        indexd_get_unavailable_bucket_func = (
            indexd_get_unavailable_s3_bucket_acl
        )
    else:
        indexd_get_unavailable_bucket_func = indexd_get_unavailable_s3_bucket

    indexd_patcher = patch(
        'fence.blueprints.data.IndexedFile._get_index_document',
        indexd_get_unavailable_bucket_func)
    mocker.add_mock(indexd_patcher)


@pytest.fixture(scope='function')
def public_indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()

    if request.param == 'gs':
        indexd_get_public_object_func = indexd_get_public_gs_object
    elif request.param == 'gs_acl':
        indexd_get_public_object_func = (
            indexd_get_public_gs_object_acl
        )
    elif request.param == 's3_acl':
        indexd_get_public_object_func = (
            indexd_get_public_s3_object_acl
        )
    else:
        indexd_get_public_object_func = indexd_get_public_s3_object

    indexd_patcher = patch(
        'fence.blueprints.data.IndexedFile._get_index_document',
        indexd_get_public_object_func)
    mocker.add_mock(indexd_patcher)


@pytest.fixture(scope='function')
def public_bucket_indexd_client(app, request):
    mocker = Mocker()
    mocker.mock_functions()

    if request.param == 'gs':
        indexd_get_public_bucket_func = indexd_get_public_gs_bucket
    elif request.param == 'gs_acl':
        indexd_get_public_bucket_func = (
            indexd_get_public_gs_bucket_acl
        )
    elif request.param == 's3_acl':
        indexd_get_public_bucket_func = (
            indexd_get_public_s3_bucket_acl
        )
    elif request.param == 's2':
        indexd_get_public_bucket_func = (
            indexd_unsupported_protocol_bucket
        )
    else:
        indexd_get_public_bucket_func = indexd_get_public_s3_bucket

    indexd_patcher = patch(
        'fence.blueprints.data.IndexedFile._get_index_document',
        indexd_get_public_bucket_func)
    mocker.add_mock(indexd_patcher)


@pytest.fixture(scope='function')
def patch_app_db_session(app, monkeypatch):
    """
    TODO
    """
    def do_patch(session):
        monkeypatch.setattr(app.db, 'Session', lambda: session)
        modules_to_patch = [
            'fence.auth',
            'fence.resources.google.utils',
            'fence.blueprints.link',
            'fence.blueprints.google',
            'fence.oidc.jwt_generator',
            'fence.user',
        ]
        for module in modules_to_patch:
            monkeypatch.setattr('{}.current_session'.format(module), session)
    return do_patch


@pytest.fixture(scope='function')
def oauth_client(app, db_session, oauth_user):
    """
    Create a confidential OAuth2 client and add it to the database along with a
    test user for the client.
    """
    url = 'https://oauth-test-client.net'
    client_id = 'test-client'
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())
    test_user = (
        db_session
        .query(models.User)
        .filter_by(id=oauth_user.user_id)
        .first()
    )
    db_session.add(models.Client(
        client_id=client_id, client_secret=hashed_secret, user=test_user,
        allowed_scopes=['openid', 'user', 'fence'], _redirect_uris=url,
        description='', is_confidential=True, name='testclient'
    ))
    db_session.commit()
    return Dict(client_id=client_id, client_secret=client_secret, url=url)


@pytest.fixture(scope='function')
def oauth_client_B(app, request, db_session):
    """
    Create a second, different OAuth2 (confidential) client and add it to the
    database along with a test user for the client.
    """
    url = 'https://oauth-test-client-B.net'
    client_id = 'test-client-B'
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())

    test_user = (
        db_session
        .query(models.User)
        .filter_by(username='test')
        .first()
    )
    if not test_user:
        test_user = models.User(username='test', is_admin=False)
        db_session.add(test_user)
    db_session.add(models.Client(
        client_id=client_id, client_secret=hashed_secret, user=test_user,
        allowed_scopes=['openid', 'user', 'fence'], _redirect_uris=url,
        description='', is_confidential=True, name='testclientb'
    ))
    db_session.commit()

    return Dict(client_id=client_id, client_secret=client_secret, url=url)


@pytest.fixture(scope='function')
def oauth_client_public(app, db_session, oauth_user):
    """
    Create a public OAuth2 client.
    """
    url = 'https://oauth-test-client-public.net'
    client_id = 'test-client-public'
    test_user = (
        db_session
        .query(models.User)
        .filter_by(id=oauth_user.user_id)
        .first()
    )
    db_session.add(models.Client(
        client_id=client_id, user=test_user,
        allowed_scopes=['openid', 'user', 'fence'], _redirect_uris=url,
        description='', is_confidential=False, name='testclient-public'
    ))
    db_session.commit()
    return Dict(client_id=client_id, url=url)


@pytest.fixture(scope='function')
def oauth_test_client(client, oauth_client):
    return OAuth2TestClient(client, oauth_client, confidential=True)


@pytest.fixture(scope='function')
def oauth_test_client_B(client, oauth_client_B):
    return OAuth2TestClient(client, oauth_client_B, confidential=True)


@pytest.fixture(scope='function')
def oauth_test_client_public(client, oauth_client_public):
    return OAuth2TestClient(client, oauth_client_public, confidential=False)


@pytest.fixture(scope='function')
def primary_google_service_account(
        app, db_session, user_client, google_proxy_group):
    service_account_id = 'test-service-account-0'
    email = fence.utils.random_str(40) + "@test.com"
    service_account = models.GoogleServiceAccount(
        google_unique_id=service_account_id,
        email=email, user_id=user_client.user_id, client_id=None,
        google_project_id='projectId-0')
    db_session.add(service_account)
    db_session.commit()
    return Dict(id=service_account_id, email=email)


@pytest.fixture(scope='function')
def google_proxy_group(app, db_session, user_client):
    group_id = 'test-proxy-group-0'
    email = fence.utils.random_str(40) + "@test.com"
    test_user = (
        db_session
        .query(models.User)
        .filter_by(id=user_client.user_id)
        .first()
    )
    test_user.google_proxy_group_id = group_id
    db_session.add(models.GoogleProxyGroup(id=group_id, email=email))
    db_session.commit()
    return Dict(id=group_id, email=email)


@pytest.fixture(scope='function')
def cloud_manager():
    manager = MagicMock()
    patch('fence.blueprints.storage_creds.google.GoogleCloudManager', manager).start()
    patch('fence.resources.google.utils.GoogleCloudManager', manager).start()
    patch('fence.scripting.fence_create.GoogleCloudManager', manager).start()
    patch('fence.resources.google.access_utils.GoogleCloudManager', manager).start()
    patch('fence.blueprints.google.GoogleCloudManager', manager).start()
    manager.return_value.__enter__.return_value.get_access_key.return_value = {
        "type": "service_account",
        "project_id": "project-id",
        "private_key_id": "some_number",
        "private_key": "-----BEGIN PRIVATE KEY-----\n....\n-----END PRIVATE KEY-----\n",
        "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
        "client_id": "...",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com"
    }
    return manager


@pytest.fixture(scope='function')
def google_signed_url():
    manager = MagicMock()
    patch(
        'fence.blueprints.data.cirrus.google_cloud.utils.get_signed_url',
        manager
    ).start()

    # Note: example outpu/format from google's docs, will not actually work
    manager.return_value = (
        'https://storage.googleapis.com/google-testbucket/testdata.txt?GoogleAccessId='
        '1234567890123@developer.gserviceaccount.com&Expires=1331155464&Signature=BCl'
        'z9e4UA2MRRDX62TPd8sNpUCxVsqUDG3YGPWvPcwN%2BmWBPqwgUYcOSszCPlgWREeF7oPGowkeKk'
        '7J4WApzkzxERdOQmAdrvshKSzUHg8Jqp1lw9tbiJfE2ExdOOIoJVmGLoDeAGnfzCd4fTsWcLbal9'
        'sFpqXsQI8IQi1493mw%3D'
    )
    return manager


@pytest.fixture(scope='function')
def mock_get(monkeypatch, example_keys_response):
    """
    Provide a function to patch the value of the JSON returned by
    ``requests.get``.

    Args:
        monkeypatch (pytest.monkeypatch.MonkeyPatch): fixture

    Return:
        Calllable[dict, None]:
            function which sets the reponse JSON of ``requests.get``
    """

    def do_patch(urls_to_responses=None):
        """
        Args:
            keys_response_json (dict): value to set /jwt/keys return value to

        Return:
            None

        Side Effects:
            Patch ``requests.get``
        """

        def get(url):
            """Define a mock ``get`` function to return a mocked response."""
            mocked_response = MagicMock(requests.Response)
            mocked_response.json.return_value = urls_to_responses[url]
            return mocked_response

        monkeypatch.setattr('requests.get', MagicMock(side_effect=get))

    return do_patch


@pytest.fixture(scope='function')
def encoded_creds_jwt(
        kid, rsa_private_key, user_client, oauth_client, google_proxy_group):
    """
    Return a JWT and user_id for a new user containing the claims and
    encoded with the private key.

    Args:
        claims (dict): fixture
        rsa_private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {'kid': kid}
    return Dict(
        jwt=jwt.encode(
            utils.authorized_download_credentials_context_claims(
                user_client['username'], user_client['user_id'],
                oauth_client['client_id'], google_proxy_group['id']),
            key=rsa_private_key,
            headers=headers,
            algorithm='RS256',
        ),
        user_id=user_client['user_id'],
        client_id=oauth_client['client_id'],
        proxy_group_id=google_proxy_group['id']
    )


@pytest.fixture(scope='function')
def encoded_jwt_no_proxy_group(
        kid, rsa_private_key, user_client, oauth_client):
    """
    Return a JWT and user_id for a new user containing the claims and
    encoded with the private key.

    Args:
        claims (dict): fixture
        rsa_private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {'kid': kid}
    return Dict(
        jwt=jwt.encode(
            utils.authorized_download_credentials_context_claims(
                user_client['username'], user_client['user_id'],
                oauth_client['client_id']),
            key=rsa_private_key,
            headers=headers,
            algorithm='RS256',
        ),
        user_id=user_client['user_id'],
        client_id=oauth_client['client_id']
    )


@pytest.fixture(scope='function')
def user_with_fence_provider(app, request, db_session):
    """
    Create a second, different OAuth2 (confidential) client and add it to the
    database along with a test user for the client.
    """
    fence_provider = (
        db_session
        .query(models.IdentityProvider)
        .filter_by(name='fence')
        .first()
    )
    if not fence_provider:
        fence_provider = models.IdentityProvider(name='fence')
        db_session.add(fence_provider)
        db_session.commit()

    test_user = (
        db_session
        .query(models.User)
        .filter_by(username='test-fence-provider')
        .first()
    )
    if test_user:
        test_user.idp_id = fence_provider.id
    else:
        test_user = models.User(
            username='test-fence-provider', is_admin=False,
            idp_id=fence_provider.id)
        db_session.add(test_user)

    db_session.commit()

    return test_user


@pytest.fixture(scope='function')
def google_storage_client_mocker(app):
    storage_client_mock = MagicMock()

    temp = app.storage_manager
    app.storage_manager.clients['google'] = storage_client_mock

    yield storage_client_mock

    app.storage_manager = temp


@pytest.fixture(scope='function')
def remove_google_idp(app):
    """
    Don't include google in the enabled idps, but leave it configured
    in the openid connect clients.
    """
    saved_app_config = copy.deepcopy(app.config)

    override_setings = {
        "ENABLED_IDENTITY_PROVIDERS": {
            # ID for which of the providers to default to.
            'default': 'fence',
            # Information for identity providers.
            'providers': {
                'fence': {
                    'name': 'Fence Multi-Tenant OAuth',
                },
                'shibboleth': {
                    'name': 'NIH Login',
                },
            },
        },
        "OPENID_CONNECT": {
            'google': {
                'client_id': '123',
                'client_secret': '456',
                'redirect_url': '789'
            }
        }
    }
    app.config.update(override_setings)

    yield

    # restore old config
    app.config = copy.deepcopy(saved_app_config)
