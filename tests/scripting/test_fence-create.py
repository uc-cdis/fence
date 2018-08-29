import time
import mock
# Python 2 and 3 compatible
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch
from mock import MagicMock
import pytest

import cirrus
from cirrus.google_cloud.errors import GoogleAuthError

from fence.jwt.validate import validate_jwt
from fence.models import (
    AccessPrivilege, Project, User, UserRefreshToken, Client,
    GoogleServiceAccount, UserServiceAccount, GoogleBucketAccessGroup,
    CloudProvider, Bucket, ServiceAccountToGoogleBucketAccessGroup
)
from fence.scripting.fence_create import (
    delete_users, JWTCreator, delete_client_action,
    delete_expired_service_accounts,
    link_external_bucket,
    verify_bucket_access_group,
    _verify_google_group_member,
    _verify_google_service_account_member,
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


def _setup_service_account_to_google_bucket_access_group(db_session):
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


def test_delete_expired_service_accounts_with_one_fail_first(cloud_manager, app, db_session):
    """
    Test the case that there is a failure of removing service account from google group
    """
    from googleapiclient.errors import HttpError
    import fence

    fence.settings = MagicMock()
    cirrus.config.update = MagicMock()
    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.side_effect = [
        HttpError(mock.Mock(status=403), 'Permission denied'), {}]
    _setup_service_account_to_google_bucket_access_group(db_session)
    service_accounts = db_session.query(UserServiceAccount).all()
    google_bucket_access_grps = db_session.query(
        GoogleBucketAccessGroup).all()

    current_time = int(time.time())

    # Add expired service account. This acccount is supposed to be deleted
    db_session.add(ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id, expires=current_time-3600,
        access_group_id=google_bucket_access_grps[0].id))

    # Add non-expired service account.
    db_session.add(ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[1].id, expires=current_time+3600,
        access_group_id=google_bucket_access_grps[1].id))
    db_session.commit()

    # check database to make sure all the service accounts exist
    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 2

    # call function to delete expired service account
    delete_expired_service_accounts(app.config['DB'])
    # check database again. Expect no service account is deleted
    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 2

def test_delete_expired_service_accounts_with_one_fail_second(cloud_manager, app, db_session):
    """
    Test the case that there is a failure of removing service account from google group
    """
    from googleapiclient.errors import HttpError
    import fence

    fence.settings = MagicMock()
    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.side_effect = [
            {}, HttpError(mock.Mock(status=403), 'Permission denied')]
    _setup_service_account_to_google_bucket_access_group(db_session)
    service_accounts = db_session.query(UserServiceAccount).all()
    google_bucket_access_grps = db_session.query(
        GoogleBucketAccessGroup).all()

    current_time = int(time.time())

    # Add two expired service account. They are both supposed to be deleted but
    # only one is deleted due to a raise exception
    service_account1 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id, expires=current_time-3600,
        access_group_id=google_bucket_access_grps[0].id)

    service_account2 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[1].id, expires=current_time-3600,
        access_group_id=google_bucket_access_grps[1].id)

    db_session.add(service_account1)
    db_session.add(service_account2)
    db_session.commit()

    # check database to make sure there are two records in DB
    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 2

    # call function to delete expired service account
    delete_expired_service_accounts(app.config['DB'])
    # check database to make sure only the first one is deleted, the second one
    # still exists because of the raised exception
    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 1
    assert records[0].id == service_account2.id


def test_delete_expired_service_accounts(cloud_manager, app, db_session):
    """
    Test deleting all expired service accounts
    """
    import fence

    fence.settings = MagicMock()
    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.return_value= {}
    _setup_service_account_to_google_bucket_access_group(db_session)
    service_accounts = db_session.query(UserServiceAccount).all()
    google_bucket_access_grps = db_session.query(
        GoogleBucketAccessGroup).all()

    current_time = int(time.time())

    # Add 2 expired and 1 not expired accounts
    service_account1 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id, expires=current_time-3600,
        access_group_id=google_bucket_access_grps[0].id)
    service_account2 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id, expires=current_time-3600,
        access_group_id=google_bucket_access_grps[1].id)
    service_account3 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[1].id, expires=current_time+3600,
        access_group_id=google_bucket_access_grps[1].id)

    db_session.add(service_account1)
    db_session.add(service_account2)
    db_session.add(service_account3)

    db_session.commit()

    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 3

    # call function to delete expired service account
    delete_expired_service_accounts(app.config['DB'])
    # check database. Expect 2 deleted
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 1
    assert records[0].id == service_account3.id


def test_delete_not_expired_service_account(app, db_session):
    """
    Test the case that there is no expired service account
    """
    import fence

    fence.settings = MagicMock()
    _setup_service_account_to_google_bucket_access_group(db_session)
    service_account = db_session.query(UserServiceAccount).first()
    google_bucket_access_grp1 = db_session.query(
        GoogleBucketAccessGroup).first()

    current_time = int(time.time())

    # Add non-expired service account
    service_account = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_account.id, expires=current_time+3600,
        access_group_id=google_bucket_access_grp1.id)
    db_session.add(service_account)
    db_session.commit()

    records = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .all()
    )
    assert len(records) == 1

    # call function to delete expired service account
    delete_expired_service_accounts(app.config['DB'])
    # check db again to make sure the record still exists
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 1


def test_verify_bucket_access_group_no_interested_accounts(app, cloud_manager, db_session, setup_test_data):
    """
    Test that Google API returns no interested accounts
    """
    import fence
    fence.settings = MagicMock()
    (
        cloud_manager.return_value.__enter__.
        return_value.get_group_members.return_value
    ) = [
            {
                'kind': "admin#directory#member",
                'etag': 'etag1',
                'id': 'id1',
                'email': 'test@gmail.com',
                'role': 'role1',
                'type': 'type'
            },
    ]

    fence.scripting.fence_create._verify_google_group_member = MagicMock()
    fence.scripting.fence_create._verify_google_service_account_member = MagicMock()
    verify_bucket_access_group(app.config['DB'])

    assert not fence.scripting.fence_create._verify_google_group_member.called
    assert not fence.scripting.fence_create._verify_google_service_account_member.called

def test_verify_bucket_access_group(app, cloud_manager, db_session, setup_test_data):
    """
    Test that Google API returns no interested accounts
    """
    import fence
    fence.settings = MagicMock()
    (
        cloud_manager.return_value.__enter__.
        return_value.get_group_members.return_value
    ) = [
            {
                'kind': "admin#directory#member",
                'etag': 'etag1',
                'id': 'id1',
                'email': 'test1@gmail.com',
                'role': 'role1',
                'type': 'type'
            },
            {
                'kind': "admin#directory#member",
                'etag': 'etag2',
                'id': 'id2',
                'email': 'test2@gmail.com',
                'role': 'role2',
                'type': 'GROUP'
            },
            {
                'kind': "admin#directory#member",
                'etag': 'etag3',
                'id': 'id3',
                'email': 'test3@gmail.com',
                'role': 'role3',
                'type': 'GROUP'
            },
            {
                'kind': "admin#directory#member",
                'etag': 'etag4',
                'id': 'id4',
                'email': 'test4@gmail.com',
                'role': 'role4',
                'type': 'USER'
            },
    ]

    fence.scripting.fence_create._verify_google_group_member = MagicMock()
    (
        fence.scripting.fence_create
        ._verify_google_service_account_member
    ) = MagicMock()
    verify_bucket_access_group(app.config['DB'])

    assert (
        fence.scripting.fence_create.
        _verify_google_group_member.call_count
    ) == 2
    assert (
        fence.scripting.fence_create.
        _verify_google_service_account_member.call_count
    ) == 1


def test_verify_google_group_member(
        app, cloud_manager, db_session, setup_test_data):
    """
    Test that successfully deletes google group members which are not in Fence
    """
    access_group = (
        db_session
        .query(GoogleBucketAccessGroup)
        .filter_by(email='access_grp_test1@gmail.com')
        .first()
    )
    member = {
        'kind': "admin#directory#member",
        'etag': 'etag4',
        'id': 'id4',
        'email': 'test4@gmail.com',
        'role': 'role4',
        'type': 'GROUP'
    }

    _verify_google_group_member(db_session, access_group, member)
    assert (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.called
    )


def test_verify_google_group_member_not_call_delete_operation(
        app, cloud_manager, db_session, setup_test_data):
    """
    Test that does not delete google group members which are in Fence
    """
    access_group = (
        db_session
        .query(GoogleBucketAccessGroup)
        .filter_by(email='access_grp_test1@gmail.com')
        .first()
    )
    member = {
        'kind': "admin#directory#member",
        'etag': 'etag4',
        'id': 'id4',
        'email': 'group1@mail.com',
        'role': 'role4',
        'type': 'GROUP'
    }

    _verify_google_group_member(db_session, access_group, member)
    assert not (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.called
    )


def test_verify_google_service_account_member_call_delete_operation(
        app, cloud_manager, db_session, setup_test_data):
    """
    Test that deletes a google user member which is not in Fence
    """
    access_group = (
        db_session
        .query(GoogleBucketAccessGroup)
        .filter_by(email='access_grp_test1@gmail.com')
        .first()
    )
    member = {
        'kind': "admin#directory#member",
        'etag': 'etag4',
        'id': 'id4',
        'email': 'deleteting@mail.com',
        'role': 'role4',
        'type': 'USER'
    }

    _verify_google_service_account_member(db_session, access_group, member)
    assert (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.called
    )


def test_verify_google_service_account_member_not_call_delete_operation(
        app, cloud_manager, db_session, setup_test_data):
    """
    Test that does not delete a google user member which is in Fence
    """
    access_group = (
        db_session
        .query(GoogleBucketAccessGroup)
        .filter_by(email='access_grp_test1@gmail.com')
        .first()
    )
    member = {
        'kind': "admin#directory#member",
        'etag': 'etag4',
        'id': 'id4',
        'email': 'user1@gmail.com',
        'role': 'role',
        'type': 'USER'
    }

    _verify_google_service_account_member(db_session, access_group, member)
    assert not (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.called
    )

def test_link_external_bucket(
        app, cloud_manager, db_session):

    (cloud_manager.return_value.__enter__.
     return_value.create_group.return_value) = (
        {'email': 'test_bucket_read_gbag@someemail.com'})

    bucket_count_before = (
        db_session.
        query(Bucket).
        count()
    )
    gbag_count_before =(
        db_session.
        query(GoogleBucketAccessGroup).
        count()
    )

    linked_gbag_email = link_external_bucket(app.config['DB'], "test_bucket")

    bucket_count_after = (
        db_session.
        query(Bucket).
        count()
    )
    gbag_count_after = (
        db_session.
        query(GoogleBucketAccessGroup).
        count()
    )

    assert (
        cloud_manager.return_value.__enter__.
        return_value.create_group.called
    )

    assert bucket_count_after == bucket_count_before + 1
    assert gbag_count_after == gbag_count_before + 1
