from flask import session
import pytest
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
from fence.errors import APIError


def test_google_link_redirect(client, app, encoded_creds_jwt):
    encoded_credentials_jwt = encoded_creds_jwt['jwt']

    r = client.get(
        '/link/google',
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    assert r.status_code == 302


def test_google_link_session(app, client, encoded_creds_jwt):
    encoded_credentials_jwt = encoded_creds_jwt['jwt']
    user_id = encoded_creds_jwt['user_id']
    proxy_group_id = encoded_creds_jwt['proxy_group_id']

    redirect = 'http://localhost'
    r = client.get(
        '/link/google?redirect=' + redirect,
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    assert session.get('google_link') is True
    assert session.get('user_id') == user_id
    assert session.get('google_proxy_group_id') == proxy_group_id
    assert session.get('redirect') == redirect


def test_google_link_auth_return(app, client, db_session, encoded_creds_jwt):
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

    add_new_g_acnt_mock = MagicMock()
    patcher = patch(
        'fence.blueprints.link._add_new_user_google_account',
        add_new_g_acnt_mock)
    patcher.start()

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    with patch('flask.current_app.google_client.get_user_id') as g_resp:
        # simulate successfully authed reponse with user email
        g_resp.return_value = {'email': google_account}

        r = client.get(
            '/link/google/link?code=' + test_auth_code)

        assert r.status_code == 302
        assert r.headers['Location'] == redirect

        assert not session.get('google_link')
        assert not session.get('user_id')
        assert not session.get('google_proxy_group_id')

    patcher.stop()


def test_google_link_g_account_exists(app, client, db_session, encoded_creds_jwt):
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

    add_new_g_acnt_mock = MagicMock()
    patcher = patch(
        'fence.blueprints.link._add_new_user_google_account',
        add_new_g_acnt_mock)
    patcher.start()

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    with patch('flask.current_app.google_client.get_user_id') as g_resp:
        # simulate successfully authed reponse with user email
        g_resp.return_value = {'email': google_account}

        r = client.get(
            '/link/google/link?code=' + test_auth_code)

        assert not add_new_g_acnt_mock.called
        assert r.status_code == 302
        assert r.headers['Location'] == redirect

        assert not session.get('google_link')
        assert not session.get('user_id')
        assert not session.get('google_proxy_group_id')

    patcher.stop()


def test_google_link_g_account_exists_linked_to_different_user(
        app, client, db_session, encoded_creds_jwt):
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

    add_new_g_acnt_mock = MagicMock()
    patcher = patch(
        'fence.blueprints.link._add_new_user_google_account',
        add_new_g_acnt_mock)
    patcher.start()

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    with patch('flask.current_app.google_client.get_user_id') as g_resp:
        # simulate successfully authed reponse with user email
        g_resp.return_value = {'email': google_account}

        r = client.get(
            '/link/google/link?code=' + test_auth_code)

        assert not add_new_g_acnt_mock.called

        # make sure we're redirecting with error information
        assert redirect in r.headers['Location']
        assert 'error=' in r.headers['Location']
        assert 'error_description=' in r.headers['Location']

        assert not session.get('google_link')
        assert not session.get('user_id')
        assert not session.get('google_proxy_group_id')

    patcher.stop()


def test_google_link_no_proxy_group(
        app, client, db_session, encoded_creds_jwt):
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

    add_new_g_acnt_mock = MagicMock()
    patcher = patch(
        'fence.blueprints.link._add_new_user_google_account',
        add_new_g_acnt_mock)
    patcher.start()

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    with patch('flask.current_app.google_client.get_user_id') as g_resp:
        # simulate successfully authed reponse with user email
        g_resp.return_value = {'email': google_account}

        r = client.get(
            '/link/google/link?code=' + test_auth_code)

        assert not add_new_g_acnt_mock.called

        # make sure we're redirecting with error information
        assert redirect in r.headers['Location']
        assert 'error=' in r.headers['Location']
        assert 'error_description=' in r.headers['Location']

        assert not session.get('google_link')
        assert not session.get('user_id')
        assert not session.get('google_proxy_group_id')

    patcher.stop()