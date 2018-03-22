import flask
import time

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

from fence.resources.storage.cdis_jwt import create_session_token
from fence.settings import SESSION_COOKIE_NAME
from fence.models import UserGoogleAccount
from fence.models import UserGoogleAccountToProxyGroup


def test_google_link_redirect(client, app, encoded_creds_jwt):
    """
    Test that when we hit the link endpoint with valid creds, we get
    a redirect response. This should be redirecting to google's oauth
    """
    encoded_credentials_jwt = encoded_creds_jwt['jwt']
    redirect = 'http://localhost'

    r = client.get(
        '/link/google?redirect=' + redirect,
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    assert r.status_code == 302
    assert r.location == flask.current_app.google_client.get_auth_url()


def test_google_link_no_redirect_provided(
        client, app, add_new_g_acnt_mock,
        google_auth_get_user_info_mock):
    """
    Test that when we hit the auth return endpoint without going through
    the auth flow and don't provide a redirect, we don't try to create anything
    or redirect.
    """
    r = client.get('/link/google/link')

    assert not add_new_g_acnt_mock.called
    assert r.status_code != 302

    assert not flask.session.get('google_link')
    assert not flask.session.get('user_id')
    assert not flask.session.get('google_proxy_group_id')


def test_google_link_session(app, client, encoded_creds_jwt):
    """
    Test the link endpoint for setting session details (this will be
    needed by the return endpoint).
    """
    encoded_credentials_jwt = encoded_creds_jwt['jwt']
    user_id = encoded_creds_jwt['user_id']
    proxy_group_id = encoded_creds_jwt['proxy_group_id']

    redirect = 'http://localhost'
    r = client.get(
        '/link/google?redirect=' + redirect,
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    assert flask.session.get('google_link') is True
    assert flask.session.get('user_id') == user_id
    assert flask.session.get('google_proxy_group_id') == proxy_group_id
    assert flask.session.get('redirect') == redirect


def test_google_link_auth_return(
        app, client, db_session, encoded_creds_jwt,
        google_auth_get_user_info_mock):
    """
    Test the link endpoint that gets hit after authN. Make sure we
    make calls to create new user google accounts and return a redirect
    with the redirect from the flask.session.
    """
    user_id = encoded_creds_jwt['user_id']
    proxy_group_id = encoded_creds_jwt['proxy_group_id']

    test_auth_code = 'abc123'
    redirect = 'http://localhost'
    google_account = 'some-authed-google-account@gmail.com'

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT"),
        context={
            'google_link': True,
            'user_id': user_id,
            'google_proxy_group_id': proxy_group_id,
            'redirect': redirect
        }
    )

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {'email': google_account}

    r = client.get(
        '/link/google/link?code=' + test_auth_code)

    assert r.status_code == 302
    assert r.headers['Location'] == redirect

    user_google_account = (
        db_session.query(UserGoogleAccount)
        .filter(
            UserGoogleAccount.email == google_account,
            UserGoogleAccount.user_id == user_id
        ).first()
    )
    assert user_google_account

    assert not flask.session.get('google_link')
    assert not flask.session.get('user_id')
    assert not flask.session.get('google_proxy_group_id')


def test_google_link_g_account_exists(
        app, client, db_session, encoded_creds_jwt, add_new_g_acnt_mock,
        google_auth_get_user_info_mock):
    """
    Test the link endpoint that gets hit after authN when the provided Google
    account is already linked. Make sure we don't attempt to create a new one
    and that we redirect with no errors
    """
    user_id = encoded_creds_jwt['user_id']
    proxy_group_id = encoded_creds_jwt['proxy_group_id']

    test_auth_code = 'abc123'
    redirect = 'http://localhost'
    google_account = 'some-authed-google-account@gmail.com'

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT"),
        context={
            'google_link': True,
            'user_id': user_id,
            'google_proxy_group_id': proxy_group_id,
            'redirect': redirect
        }
    )

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {'email': google_account}

    r = client.get(
        '/link/google/link?code=' + test_auth_code)

    assert not add_new_g_acnt_mock.called
    assert r.status_code == 302
    assert r.headers['Location'] == redirect

    assert not flask.session.get('google_link')
    assert not flask.session.get('user_id')
    assert not flask.session.get('google_proxy_group_id')


def test_google_link_g_account_access_extension(
        app, client, db_session, encoded_creds_jwt, add_new_g_acnt_mock,
        google_auth_get_user_info_mock):
    """
    Test the link endpoint that gets hit after authN when the provided Google
    account is already linked. This time test if we correctly extend the
    google accounts access.
    """
    user_id = encoded_creds_jwt['user_id']
    proxy_group_id = encoded_creds_jwt['proxy_group_id']

    original_expiration = 1000
    test_auth_code = 'abc123'
    redirect = 'http://localhost'
    google_account = 'some-authed-google-account@gmail.com'

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT"),
        context={
            'google_link': True,
            'user_id': user_id,
            'google_proxy_group_id': proxy_group_id,
            'redirect': redirect
        }
    )

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()
    g_account_access = UserGoogleAccountToProxyGroup(
            user_google_account_id=existing_account.id,
            proxy_group_id=proxy_group_id,
            expires=original_expiration
    )
    db_session.add(g_account_access)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {'email': google_account}

    r = client.get(
        '/link/google/link?code=' + test_auth_code)

    account_in_proxy_group = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id
            == existing_account.id
        ).first()
    )
    assert account_in_proxy_group.proxy_group_id == proxy_group_id

    # check that expiration changed and that it's less than the cfg
    # expires in (since this check will happen a few seconds after
    # it gets set)
    assert account_in_proxy_group.expires != original_expiration
    assert account_in_proxy_group.expires <= (
        int(time.time())
        + flask.current_app.config['GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN']
    )

    assert not add_new_g_acnt_mock.called
    assert r.status_code == 302
    assert r.headers['Location'] == redirect

    assert not flask.session.get('google_link')
    assert not flask.session.get('user_id')
    assert not flask.session.get('google_proxy_group_id')


def test_google_link_g_account_exists_linked_to_different_user(
        app, client, db_session, encoded_creds_jwt, add_new_g_acnt_mock,
        google_auth_get_user_info_mock):
    """
    Test the link endpoint that gets hit after authN when the provided Google
    account is already linked to a different user. We should not attempt to
    create a new user google account and just redirect with
    an error.
    """
    user_id = encoded_creds_jwt['user_id']
    proxy_group_id = encoded_creds_jwt['proxy_group_id']

    test_auth_code = 'abc123'
    redirect = 'http://localhost'
    google_account = 'some-authed-google-account@gmail.com'

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT"),
        context={
            'google_link': True,
            'user_id': user_id+5,  # <- NOT the user whose g acnt exists
            'google_proxy_group_id': proxy_group_id,
            'redirect': redirect
        }
    )

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {'email': google_account}

    r = client.get(
        '/link/google/link?code=' + test_auth_code)

    assert not add_new_g_acnt_mock.called

    # make sure we're redirecting with error information
    assert redirect in r.headers['Location']
    assert 'error=' in r.headers['Location']
    assert 'error_description=' in r.headers['Location']

    assert not flask.session.get('google_link')
    assert not flask.session.get('user_id')
    assert not flask.session.get('google_proxy_group_id')


def test_google_link_no_proxy_group(
        app, client, db_session, encoded_creds_jwt, add_new_g_acnt_mock,
        google_auth_get_user_info_mock):
    user_id = encoded_creds_jwt['user_id']

    test_auth_code = 'abc123'
    redirect = 'http://localhost'
    google_account = 'some-authed-google-account@gmail.com'

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT"),
        context={
            'google_link': True,
            'user_id': user_id,
            'google_proxy_group_id': None,  # <- no proxy group
            'redirect': redirect
        }
    )

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {'email': google_account}

    r = client.get(
        '/link/google/link?code=' + test_auth_code)

    assert not add_new_g_acnt_mock.called

    # make sure we're redirecting with error information
    assert redirect in r.headers['Location']
    assert 'error=' in r.headers['Location']
    assert 'error_description=' in r.headers['Location']

    assert not flask.session.get('google_link')
    assert not flask.session.get('user_id')
    assert not flask.session.get('google_proxy_group_id')
