# Python 2 and 3 compatible
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from fence.models import AccessPrivilege, Project, User, UserRefreshToken
from fence.scripting.fence_create import (
    delete_users,
    create_user_refresh_token,
    create_user_access_token,
    get_jwt_keypair,
)

from fence.jwt.validate import validate_jwt


ROOT_DIR = './'


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


def test_get_jwt_keypair_with_default_kid(mock_keypairs, kid):
    result_kid, _ = get_jwt_keypair(kid=None, root_dir=ROOT_DIR)
    assert result_kid == kid


def test_get_jwt_keypair_with_no_kid_found(mock_keypairs):
    result_kid, _ = get_jwt_keypair(kid='No kid found', root_dir=ROOT_DIR)
    assert result_kid == None


def test_get_jwt_with_found_kid(mock_keypairs, kid_2):
    result_kid, _ = get_jwt_keypair(kid=kid_2, root_dir='/fake_root_dir')
    assert result_kid == kid_2


def test_create_user_access_token_with_no_found_user(
        app, mock_keypairs, db_session, kid):
    user = User(username='test_user')
    db_session.add(user)
    jti, _, _ = create_user_access_token(
        app.config['DB'], app.config['BASE_URL'], ROOT_DIR='/fake_root_dir',
        kid=kid, username='other user', scopes='fence', expires_in=3600
    )
    assert jti == None


def test_create_user_refresh_token_with_no_found_user(
        app, mock_keypairs, db_session, kid):
    user = User(username='test_user')
    db_session.add(user)
    jti, _, _ = create_user_refresh_token(
        app.config['DB'], app.config['BASE_URL'], ROOT_DIR, kid=kid,
        username='other user', scopes='fence', expires_in=3600
    )
    assert jti == None


def test_create_user_access_token_with_found_user(
        app, db_session, client, kid, rsa_private_key):
    user = User(username='test_user')
    db_session.add(user)
    with patch("fence.scripting.fence_create.get_jwt_keypair") as patch_get_jwt_keypair:
        patch_get_jwt_keypair.return_value = [kid, rsa_private_key]

        jti, access_token, _ = create_user_access_token(
            app.config['DB'], app.config['BASE_URL'], '/fake_root_dir',
            kid=kid, username='test_user', scopes='openid,user',
            expires_in=3600
        )
        r = client.get(
            '/user', headers={'Authorization': 'bear ' + access_token})
        assert r.status_code == 200
        print(r.data)
        assert jti is not None


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

    with patch("fence.scripting.fence_create.get_jwt_keypair") as patch_get_jwt_keypair:
        patch_get_jwt_keypair.return_value = [kid, rsa_private_key]

        jti, refresh_token, original_claims = create_user_refresh_token(
            DB=DB, BASE_URL=BASE_URL, ROOT_DIR='/fake_root_dir', kid=kid,
            username=username, scopes=scopes, expires_in=expires_in
        )

        refresh_token_response = (
            oauth_test_client
            .refresh(refresh_token=refresh_token)
            .response
        )

        ret_claims = validate_jwt(
            refresh_token_response.json['id_token'], {'openid'}
        )
        assert original_claims['iss'] == ret_claims['iss']
        assert original_claims['sub'] == ret_claims['sub']
        assert original_claims['iat'] <= ret_claims['iat']
        db_token = db_session.query(
            UserRefreshToken).filter_by(jti=jti).first()
        assert db_token is not None
        assert jti is not None
