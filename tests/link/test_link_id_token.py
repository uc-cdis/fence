# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

import jwt

from fence.resources.storage.cdis_jwt import create_session_token
from fence.resources.google.utils import get_linked_google_account_info
from fence.settings import SESSION_COOKIE_NAME
from fence.models import Client, UserGoogleAccount, UserGoogleAccountToProxyGroup
from fence.utils import split_url_and_query_params
from fence.jwt.token import generate_signed_id_token


def test_google_id_token_not_linked(oauth_test_client):
    """
    Test that a non-linked account does not have the google account information
    """
    data = {'confirm': 'yes'}
    oauth_test_client.authorize(data=data)
    tokens = oauth_test_client.token()
    id_token = jwt.decode(tokens.id_token, verify=False)
    assert id_token['context']['user'].get('google') is None


def test_google_id_token_linked(
        app, client, db_session, encoded_creds_jwt, oauth_test_client):
    """
    Test extending expiration for previously linked G account access via PATCH.
    """
    encoded_credentials_jwt = encoded_creds_jwt['jwt']
    user_id = encoded_creds_jwt['user_id']
    proxy_group_id = encoded_creds_jwt['proxy_group_id']

    original_expiration = 1000
    google_account = 'some-authed-google-account@gmail.com'

    test_session_jwt = create_session_token(
        app.keypairs[0],
        app.config.get("SESSION_TIMEOUT"),
        context={
            'google_proxy_group_id': proxy_group_id,
            'linked_google_email': google_account
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
    # client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)
    #
    # r = client.patch(
    #     '/link/google',
    #     headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})
    #
    # assert r.status_code == 200

    # get link from database
    account_in_proxy_group = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id
            == existing_account.id
        ).first()
    )
    assert account_in_proxy_group.proxy_group_id == proxy_group_id

    # get google account info and test
    g_account_info = get_linked_google_account_info(user_id)
    print(g_account_info)
    assert g_account_info.get('linked_google_email') == google_account
    assert g_account_info.get('linked_google_account_exp') == account_in_proxy_group.expires

    # get the id token through the actual endpoint
    data = {'confirm': 'yes'}
    oauth_test_client.authorize(data=data)
    tokens = oauth_test_client.token()
    id_token = jwt.decode(tokens.id_token, verify=False)

    assert 'google' in id_token['context']['user']
    assert id_token['context']['user']['google'].get('linked_google_account') == google_account
    assert id_token['context']['user']['google'].get('linked_google_account_exp') == account_in_proxy_group.expires

