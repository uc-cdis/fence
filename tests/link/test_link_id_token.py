import jwt

from fence.resources.google.utils import (
    get_linked_google_account_email,
    get_linked_google_account_exp,
)
from fence.models import UserGoogleAccount, UserGoogleAccountToProxyGroup


def test_google_id_token_not_linked(oauth_test_client):
    """
    Test google email and link expiration are in id_token for a linked account
    """
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    tokens = oauth_test_client.token()
    id_token = jwt.decode(tokens.id_token, verify=False)
    assert id_token["context"]["user"].get("google") is None


def test_google_id_token_linked(db_session, encoded_creds_jwt, oauth_test_client):
    """
    Test google email and link expiration are in id_token for a linked account
    """
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    original_expiration = 1000
    google_account = "some-authed-google-account@gmail.com"

    # add google account and link
    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()
    g_account_access = UserGoogleAccountToProxyGroup(
        user_google_account_id=existing_account.id,
        proxy_group_id=proxy_group_id,
        expires=original_expiration,
    )
    db_session.add(g_account_access)
    db_session.commit()

    # get google account info with utility function
    assert get_linked_google_account_email(user_id) == google_account
    assert get_linked_google_account_exp(user_id) == original_expiration

    # get the id token through endpoint
    data = {"confirm": "yes"}
    oauth_test_client.authorize(data=data)
    tokens = oauth_test_client.token()
    id_token = jwt.decode(tokens.id_token, verify=False)

    assert "google" in id_token["context"]["user"]
    assert (
        id_token["context"]["user"]["google"].get("linked_google_account")
        == google_account
    )
    assert (
        id_token["context"]["user"]["google"].get("linked_google_account_exp")
        == original_expiration
    )
