import time
# Python 2 and 3 compatible
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch
from mock import MagicMock
import pytest

import cirrus

from fence.jwt.validate import validate_jwt
from fence.models import (
    AccessPrivilege, Project, User, UserRefreshToken, Client,
    GoogleServiceAccount, UserServiceAccount, GoogleBucketAccessGroup,
    CloudProvider, Bucket, ServiceAccountToGoogleBucketAccessGroup
)
from fence.scripting.fence_create import (
    delete_users, JWTCreator, delete_client_action,
    delete_expired_service_accounts
)


ROOT_DIR = './'


def test_client_delete(app, db_session, cloud_manager, test_user_a):
    """
    Test that the client delete function correctly cleans up the client's
    service accounts and the client themself.
    """
    client_name = 'test123'
    client = Client(
        client_id=client_name,
        client_secret='secret',
        name=client_name
    )
    db_session.add(client)
    db_session.commit()

    client_service_account = GoogleServiceAccount(
        google_unique_id='jf09238ufposijf',
        client_id=client.client_id,
        user_id=test_user_a['user_id'],
        google_project_id='test',
        email='someemail@something.com'
    )
    db_session.add(client_service_account)
    db_session.commit()

    # empty return means success
    (
        cloud_manager.return_value
        .__enter__.return_value
        .delete_service_account.return_value
    ) = {}

    delete_client_action(app.config['DB'], client_name)

    client_after = db_session.query(Client).filter_by(name=client_name).all()
    client_service_account_after = (
        db_session.query(GoogleServiceAccount)
        .filter_by(client_id=client.client_id)
    ).all()
    assert len(client_after) == 0
    assert len(client_service_account_after) == 0


def test_client_delete_error(app, db_session, cloud_manager, test_user_a):
    """
    Test that when Google gives us an error when deleting the service account,
    we don't remove it from the db.
    """
    client_name = 'test123'
    client = Client(
        client_id=client_name,
        client_secret='secret',
        name=client_name
    )
    db_session.add(client)
    db_session.commit()

    client_service_account = GoogleServiceAccount(
        google_unique_id='jf09238ufposijf',
        client_id=client.client_id,
        user_id=test_user_a['user_id'],
        google_project_id='test',
        email='someemail@something.com'
    )
    db_session.add(client_service_account)
    db_session.commit()

    # error when deleting service account
    (
        cloud_manager.return_value
        .__enter__.return_value
        .delete_service_account.return_value
    ) = {'error': 'something bad happened'}

    delete_client_action(app.config['DB'], client_name)

    client_after = db_session.query(Client).filter_by(name=client_name).all()
    client_service_account_after = (
        db_session.query(GoogleServiceAccount)
        .filter_by(client_id=client.client_id)
    ).all()

    # make sure client is deleted but service account we couldn't delete stays
    assert len(client_after) == 0
    assert len(client_service_account_after) == 1


def test_delete_users(app, db_session, example_usernames):
    """
    Test the basic functionality of ``delete_users``.
    """
    for username in example_usernames:
        db_session.add(User(username=username))
        db_session.commit()
    # Delete all but the first user; check that the first one is still there
    # and the rest are gone.
    delete_users(app.config['DB'], example_usernames[1:])
    # Get the list of usernames for users that still exist.
    # (The `list(zip(...))` trick is to turn a list of 1-tuples into a
    # flattened list.)
    remaining_usernames = list(zip(*db_session.query(User.username).all())[0])
    assert example_usernames[0] in remaining_usernames
    for username in example_usernames[1:]:
        assert username not in remaining_usernames


def test_delete_user_with_access_privilege(app, db_session):
    user = User(username='test-user-with-privilege')
    project = Project(id=1, name='test-project')
    access_privilege = AccessPrivilege(
        user=user,
        privilege=['read'],
        project=project,
    )
    db_session.add(user)
    db_session.add(project)
    db_session.add(access_privilege)
    db_session.commit()
    delete_users(app.config['DB'], [user.username])
    remaining_usernames = db_session.query(User.username).all()
    assert db_session.query(User).count() == 0, remaining_usernames


def test_create_user_access_token_with_no_found_user(
        app, db_session, kid, rsa_private_key):
    user = User(username='test_user')
    db_session.add(user)
    jwt_creator = JWTCreator(
        app.config['DB'], app.config['BASE_URL'], kid=kid,
        username='other user', scopes='fence', expires_in=3600,
        private_key=rsa_private_key
    )
    with pytest.raises(EnvironmentError):
        jwt_creator.create_access_token()


def test_create_user_refresh_token_with_no_found_user(
        app, db_session, kid, rsa_private_key):
    user = User(username='test_user')
    db_session.add(user)
    jwt_creator = JWTCreator(
        app.config['DB'], app.config['BASE_URL'], kid=kid,
        username='other user', scopes='fence', expires_in=3600,
        private_key=rsa_private_key
    )
    with pytest.raises(EnvironmentError):
        jwt_creator.create_refresh_token()


def test_create_user_access_token_with_found_user(
        app, db_session, client, kid, rsa_private_key, oauth_client):
    user = User(username='test_user')
    db_session.add(user)

    jwt_result = (
        JWTCreator(
            app.config['DB'], app.config['BASE_URL'], kid=kid,
            username='test_user', scopes=['openid', 'user'], expires_in=3600,
            private_key=rsa_private_key
        )
        .create_access_token()
    )
    r = client.get(
        '/user', headers={'Authorization': 'bear ' + jwt_result.token})
    assert r.status_code == 200
    assert jwt_result.claims


def test_create_refresh_token_with_found_user(
        app, db_session, oauth_test_client, kid, rsa_private_key):

    DB = app.config['DB']
    username = 'test_user'
    BASE_URL = app.config['BASE_URL']
    scopes = 'openid,user'
    expires_in = 3600

    user = User(username=username)
    db_session.add(user)

    user = (db_session.query(User)
            .filter_by(username=username)
            .first()
            )

    jwt_result = (
        JWTCreator(
            DB, BASE_URL, kid=kid, username=username, scopes=scopes,
            expires_in=expires_in, private_key=rsa_private_key
        )
        .create_refresh_token()
    )

    refresh_token_response = (
        oauth_test_client
        .refresh(refresh_token=jwt_result.token)
        .response
    )

    ret_claims = validate_jwt(
        refresh_token_response.json['id_token'], {'openid'}
    )
    assert jwt_result.claims['iss'] == ret_claims['iss']
    assert jwt_result.claims['sub'] == ret_claims['sub']
    assert jwt_result.claims['iat'] <= ret_claims['iat']
    db_token = (
        db_session
        .query(UserRefreshToken)
        .filter_by(jti=jwt_result.claims['jti'])
        .first()
    )
    assert db_token is not None


def setup_service_account_to_google_bucket_access_group(db_session):
    """
    Setup some testing data.
    """
    cloud_provider = CloudProvider(name='test_provider', endpoint='https://test.com',
                        backend='test_backend', description='description', service='service')
    db_session.add(cloud_provider)

    db_session.add(UserServiceAccount(google_unique_id='test_id1',
                        email='test1@gmail.com', google_project_id='efewf444'))
    db_session.add(UserServiceAccount(google_unique_id='test_id2',
                        email='test2@gmail.com', google_project_id='edfwf444'))
    db_session.commit()

    bucket1 = Bucket(name='test_bucket1', provider_id=cloud_provider.id)
    db_session.add(bucket1)
    db_session.commit()

    db_session.add(GoogleBucketAccessGroup(
        bucket_id=bucket1.id, email='testgroup1@gmail.com',
        privileges=['read_storage', 'write_storage']))
    db_session.add(GoogleBucketAccessGroup(
        bucket_id=bucket1.id, email='testgroup2@gmail.com',
        privileges=['read_storage']))
    db_session.commit()


def test_delete_expired_service_accounts_with_one_fail(cloud_manager, app, db_session):
    """
    Test the case that there is a failure to remove service account from google group
    """
    from googleapiclient.errors import HttpError

    def side_effect_function(param1, param2):
        import mock
        raise HttpError(mock.Mock(status=403), 'Permission denied')

    cloud_manager.mocked_init.return_value = None
    cloud_manager.mocked_remove_member_from_group.side_effect = [side_effect_function, {}]
    setup_service_account_to_google_bucket_access_group(db_session)
    service_accounts = db_session.query(UserServiceAccount).all()
    google_bucket_access_grps = db_session.query(
        GoogleBucketAccessGroup).all()

    current_time = int(time.time())
    db_session.add(ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id, expires=current_time-1,
        access_group_id=google_bucket_access_grps[0].id))

    db_session.add(ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[1].id, expires=current_time+300,
        access_group_id=google_bucket_access_grps[1].id))
    db_session.commit()

    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 2

    delete_expired_service_accounts(app.config['DB'])
    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 1


def test_delete_expired_service_accounts(cloud_manager, app, db_session):
    """
    Test deleting all expired service accounts
    """
    cloud_manager.mocked_init.return_value = None
    cloud_manager.mocked_remove_member_from_group.return_value = {}
    setup_service_account_to_google_bucket_access_group(db_session)
    service_accounts = db_session.query(UserServiceAccount).all()
    google_bucket_access_grps = db_session.query(
        GoogleBucketAccessGroup).all()

    current_time = int(time.time())

    # setup 2 expired and 1 not expired accounts
    db_session.add(ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id, expires=current_time-1,
        access_group_id=google_bucket_access_grps[0].id)
        )

    db_session.add(ServiceAccountToGoogleBucketAccessGroup(
         service_account_id=service_accounts[0].id, expires=current_time+3600,
         access_group_id=google_bucket_access_grps[1].id)
        )

    db_session.add(ServiceAccountToGoogleBucketAccessGroup(
         service_account_id=service_accounts[1].id, expires=current_time-3600,
         access_group_id=google_bucket_access_grps[1].id)
         )
    db_session.commit()
    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 3
    delete_expired_service_accounts(app.config['DB'])
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 1


def test_delete_not_expired_service_account(app, db_session):
    """
    Test the case that there is no expired service account
    """
    setup_service_account_to_google_bucket_access_group(db_session)

    service_account = db_session.query(UserServiceAccount).first()
    google_bucket_access_grp1 = db_session.query(
        GoogleBucketAccessGroup).first()

    current_time = int(time.time())
    deleting_account = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_account.id, expires=current_time+3600,
        access_group_id=google_bucket_access_grp1.id)
    db_session.add(deleting_account)
    db_session.commit()
    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 1
    delete_expired_service_accounts(app.config['DB'])
    db_session.commit()
    record = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()

    assert len(record) == 1
