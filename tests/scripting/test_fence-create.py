import uuid
from fence.models import AccessPrivilege, Project, User, UserRefreshToken

from fence.scripting.fence_create import (
    delete_users,
    create_user_refresh_token,
    create_user_access_token,
    get_jwt_keypair,
)


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

def test_get_jwt_keypair_with_default_kid(mock_keypairs):
    kid, private_key = get_jwt_keypair(kid=None)
    assert kid == 'key-test'

def test_get_jwt_keypair_with_no_kid_found(mock_keypairs):
    kid, private_key = get_jwt_keypair(kid='No kid found ')
    assert kid == None

def test_get_jwt_with_found_kid(mock_keypairs):
    kid, private_key = get_jwt_keypair(kid='key-test-2')
    assert kid == 'key-test-2'

def test_create_user_access_token_with_no_found_user(app, mock_keypairs, db_session):
    user = User(username='test_user')
    db_session.add(user)
    jti, _ = create_user_access_token(
        app.config['DB'], app.config['BASE_URL'],
        kid='key-test', username='other user',
        scopes='fence', expires_in=3600
    )
    assert jti == None

def test_create_user_refresh_token_with_no_found_user(app, mock_keypairs, db_session):
    user = User(username='test_user')
    db_session.add(user)
    jti, _ = create_user_refresh_token(
        app.config['DB'], app.config['BASE_URL'],
        kid='key-test', username='other user',
        scopes='fence', expires_in=3600
    )
    assert jti == None

def test_create_user_access_token_with_found_user(app, mock_keypairs, db_session):
    user = User(username='test_user')
    db_session.add(user)
    jti, _ = create_user_access_token(
        app.config['DB'], app.config['BASE_URL'],
        kid='key-test', username='test_user',
        scopes='fence,oidc', expires_in=3600
        )
    assert jti is not None

def test_create_refresh_token_with_found_user(app, mock_keypairs, db_session):
    user = User(username='test_user')
    db_session.add(user)
    jti, _ = create_user_refresh_token(
        app.config['DB'], app.config['BASE_URL'],
        kid='key-test', username='test_user',
        scopes='fence,oidc', expires_in=3600
        )
    assert jti is not None

def test_create_refresh_token(app, mock_keypairs, db_session):
    user = User(username='test_user')
    db_session.add(user)
    jti, _ = create_user_refresh_token(
        app.config['DB'], app.config['BASE_URL'],
        kid=None, username='test_user',
        scopes=['fence'], expires_in=3600
    )
    db_token = db_session.query(UserRefreshToken).filter_by(jti=jti).first()
    assert db_token is not None
