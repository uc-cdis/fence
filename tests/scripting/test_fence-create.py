# Python 2 and 3 compatible
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import pytest

from fence.jwt.validate import validate_jwt
from fence.models import (
    AccessPrivilege, Project, User, UserRefreshToken, Client,
    GoogleServiceAccount
)
from fence.scripting.fence_create import (
    delete_users, JWTCreator, delete_client_action
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
