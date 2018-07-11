# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

from fence.resources.storage.cdis_jwt import create_session_token
from fence.resources.google.utils import get_linked_google_account_info
from fence.settings import SESSION_COOKIE_NAME
from fence.models import Client, UserGoogleAccount, UserGoogleAccountToProxyGroup
from fence.utils import split_url_and_query_params
from fence.jwt.token import generate_signed_id_token


def test_google_not_linked_id_token(oauth_test_client):
    """
    Test the following procedure:
    - ``POST /oauth2/authorize`` successfully to obtain code
    - ``POST /oauth2/token`` successfully to obtain token
    - Expect id_token to not have google account information
    """
    data = {'confirm': 'yes'}
    oauth_test_client.authorize(data=data)
    toke = oauth_test_client.token()
    print(toke)
    id_token = toke.id_token
    print(id_token)
    assert id_token['context']['user'].get('google') is None


def test_google_id_token_no_link(
        app, client, db_session, encoded_creds_jwt,
        google_auth_get_user_info_mock,
        add_google_email_to_proxy_group_mock,
        oauth_test_client):
    """
    Test extending expiration for previously linked G account access via PATCH.
    """
    encoded_credentials_jwt = encoded_creds_jwt['jwt']
    # get user from client id
    user = db_session.query(Client).filter_by(client_id=oauth_test_client.client_id).first().user
    print(user)
    user_id = user.id # encoded_creds_jwt['user_id']
    proxy_group_id = encoded_creds_jwt['proxy_group_id']

    
    print(user_id)

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
    client.set_cookie("localhost", SESSION_COOKIE_NAME, test_session_jwt)

    r = client.patch(
        '/link/google',
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    assert r.status_code == 200

    account_in_proxy_group = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id
            == existing_account.id
        ).first()
    )
    assert account_in_proxy_group.proxy_group_id == proxy_group_id

    # get google account info
    g_account_info = get_linked_google_account_info(user_id)
    print(g_account_info)
    # assert g_account_info.get('linked_google_email') == google_account
    # assert g_account_info.get('linked_google_account_exp') != original_expiration
    print("Hi")

    # get the id token through the oauth test client
    id_token = oauth_test_client.token().id_token
    print(id_token)

