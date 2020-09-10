import flask
import time
from urllib.parse import urlparse, parse_qs, urlunparse

from unittest.mock import MagicMock, patch

from fence.resources.storage.cdis_jwt import create_session_token
from fence.config import config
from fence.models import UserGoogleAccount
from fence.models import UserGoogleAccountToProxyGroup
from fence.utils import split_url_and_query_params


def test_google_link_redirect(client, app, encoded_creds_jwt):
    """
    Test that when we hit the link endpoint with valid creds, we get
    a redirect response. This should be redirecting to google's oauth
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    redirect = "http://localhost"

    r = client.get(
        "/link/google",
        query_string={"redirect": redirect},
        headers={"Authorization": "Bearer " + encoded_credentials_jwt},
    )

    assert r.status_code == 302
    url, query_params = split_url_and_query_params(r.location)
    google_url, google_query_params = split_url_and_query_params(
        app.google_client.get_auth_url()
    )
    assert google_url == url


def test_google_link_expires_in(client, app, encoded_creds_jwt):
    """
    Test success when we hit the link endpoint with a valid expires_in and
    failure with an invalid expires_in
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    redirect = "http://localhost"

    # invalid expires_in: should fail
    requested_exp = "abc"  # expires_in must be int >0

    r = client.get(
        "/link/google",
        query_string={"redirect": redirect, "expires_in": requested_exp},
        headers={"Authorization": "Bearer " + encoded_credentials_jwt},
    )
    assert r.status_code == 400  # check if failure

    # valid expires_in: should succeed
    requested_exp = 60

    r = client.get(
        "/link/google",
        query_string={"redirect": redirect, "expires_in": requested_exp},
        headers={"Authorization": "Bearer " + encoded_credentials_jwt},
    )
    assert r.status_code == 302  # check if success


def test_google_link_redirect_no_google_idp(
    client, app, restore_config, encoded_creds_jwt
):
    """
    Test that even if Google is not configured as an IDP, when we hit the link
    endpoint with valid creds, we get a redirect response.
    This should be redirecting to google's oauth
    """
    # Don't include google in the enabled idps, but leave it configured
    # in the openid connect clients:
    override_settings = {
        "LOGIN_OPTIONS": [
            {"idp": "fence", "name": "Fence Multi-Tenant OAuth"},
            {"idp": "shibboleth", "name": "NIH Login"},
        ],
        "OPENID_CONNECT": {
            "google": {
                "client_id": "123",
                "client_secret": "456",
                "redirect_url": "789",
            }
        },
    }
    config.update(override_settings)

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    redirect = "http://localhost"

    r = client.get(
        "/link/google",
        query_string={"redirect": redirect},
        headers={"Authorization": "Bearer " + encoded_credentials_jwt},
    )

    assert r.status_code == 302
    url, query_params = split_url_and_query_params(r.location)
    google_url, google_query_params = split_url_and_query_params(
        app.google_client.get_auth_url()
    )
    assert google_url == url


def test_google_link_no_redirect_provided(
    client, app, add_new_g_acnt_mock, google_auth_get_user_info_mock
):
    """
    Test that when we hit the auth return endpoint without going through
    the auth flow and don't provide a redirect, we don't try to create anything
    or redirect.
    """
    r = client.get("/link/google/callback")

    assert not add_new_g_acnt_mock.called
    assert r.status_code != 302

    assert not flask.session.get("google_link")
    assert not flask.session.get("user_id")
    assert not flask.session.get("google_proxy_group_id")


def test_google_link_session(app, client, encoded_creds_jwt):
    """
    Test the link endpoint for setting session details (this will be
    needed by the return endpoint).
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    redirect = "http://localhost"
    r = client.get(
        "/link/google",
        query_string={"redirect": redirect},
        headers={"Authorization": "Bearer " + encoded_credentials_jwt},
    )

    assert flask.session.get("google_link") is True
    assert flask.session.get("user_id") == user_id
    assert flask.session.get("google_proxy_group_id") == proxy_group_id
    assert flask.session.get("redirect") == redirect


def test_google_link_auth_return(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
):
    """
    Test the link endpoint that gets hit after authN. Make sure we
    make calls to create new user google accounts and return a redirect
    with the redirect from the flask.session.
    """
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    test_auth_code = "abc123"
    redirect = "http://localhost"
    google_account = "some-authed-google-account@gmail.com"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={
            "google_link": True,
            "user_id": user_id,
            "google_proxy_group_id": proxy_group_id,
            "redirect": redirect,
        },
    )

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {"email": google_account}

    r = client.get("/link/google/callback", query_string={"code": test_auth_code})

    assert r.status_code == 302
    parsed_url = urlparse(r.headers["Location"])
    query_params = parse_qs(parsed_url.query)
    response_redirect = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", "")
    )
    assert "exp" in query_params
    assert query_params["linked_email"][0] == google_account
    assert response_redirect == redirect

    user_google_account = (
        db_session.query(UserGoogleAccount)
        .filter(
            UserGoogleAccount.email == google_account,
            UserGoogleAccount.user_id == user_id,
        )
        .first()
    )
    assert user_google_account

    assert not flask.session.get("google_link")
    assert not flask.session.get("user_id")
    assert not flask.session.get("google_proxy_group_id")

    assert add_google_email_to_proxy_group_mock.called
    # TODO assert add_google_email_to_proxy_group_mock called with correct junk


def test_patch_google_link(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
):
    """
    Test extending expiration for previously linked G account access via PATCH.
    Test valid and invalid expires_in parameters.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    original_expiration = 1000
    google_account = "some-authed-google-account@gmail.com"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={
            "google_proxy_group_id": proxy_group_id,
            "linked_google_email": google_account,
        },
    )

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

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    r = client.patch(
        "/link/google", headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    assert r.status_code == 200

    account_in_proxy_group = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id == existing_account.id
        )
        .first()
    )
    assert account_in_proxy_group.proxy_group_id == proxy_group_id

    # check that expiration changed and that it's less than the cfg
    # expires in (since this check will happen a few seconds after
    # it gets set)
    updated_expiration = account_in_proxy_group.expires
    assert updated_expiration != original_expiration
    assert updated_expiration <= (
        int(time.time()) + config["GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN"]
    )

    assert not add_google_email_to_proxy_group_mock.called

    # invalid expires_in: should fail
    requested_exp = "abc"  # expires_in must be int >0
    r = client.patch(
        "/link/google?expires_in={}".format(requested_exp),
        headers={"Authorization": "Bearer " + encoded_credentials_jwt},
    )
    assert r.status_code == 400

    # valid expires_in: should succeed
    requested_exp = 60
    r = client.patch(
        "/link/google?expires_in={}".format(requested_exp),
        headers={"Authorization": "Bearer " + encoded_credentials_jwt},
    )
    assert r.status_code == 200

    account_in_proxy_group = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id == existing_account.id
        )
        .first()
    )
    # make sure the link is valid for the requested time
    # (allow up to 15 sec for runtime)
    diff = account_in_proxy_group.expires - int(time.time())
    assert requested_exp <= diff <= requested_exp + 15


def test_patch_google_link_account_not_in_token(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
):
    """
    Test extending expiration for previously linked G account access via PATCH.

    This will test the case where the linking happened during the life
    of an access token and the same access token is used here (e.g.
    account exists but a new token hasn't been generated with the linkage
    info yet)
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    original_expiration = 1000
    google_account = "some-authed-google-account@gmail.com"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={"google_proxy_group_id": proxy_group_id},
    )

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

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    r = client.patch(
        "/link/google", headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    assert r.status_code == 200

    account_in_proxy_group = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id == existing_account.id
        )
        .first()
    )
    assert account_in_proxy_group.proxy_group_id == proxy_group_id

    # check that expiration changed and that it's less than the cfg
    # expires in (since this check will happen a few seconds after
    # it gets set)
    assert account_in_proxy_group.expires != original_expiration
    assert account_in_proxy_group.expires <= (
        int(time.time()) + config["GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN"]
    )

    assert not add_google_email_to_proxy_group_mock.called


def test_patch_google_link_account_doesnt_exist(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
):
    """
    Test extending expiration for an unlinked G account access via PATCH.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={"google_proxy_group_id": proxy_group_id},
    )

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    r = client.patch(
        "/link/google", headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    assert r.status_code == 404

    # make sure accounts weren't created
    g_account = (
        db_session.query(UserGoogleAccount)
        .filter(UserGoogleAccount.user_id == user_id)
        .first()
    )
    assert not g_account

    account_in_proxy_group = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter(UserGoogleAccountToProxyGroup.proxy_group_id == proxy_group_id)
        .first()
    )
    assert not account_in_proxy_group

    assert not add_google_email_to_proxy_group_mock.called


def test_google_link_g_account_exists(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    add_new_g_acnt_mock,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
):
    """
    Test the link endpoint that gets hit after authN when the provided Google
    account is already linked. Make sure we don't attempt to create a new one
    and that we redirect with no errors
    """
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    test_auth_code = "abc123"
    redirect = "http://localhost"
    google_account = "some-authed-google-account@gmail.com"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={
            "google_link": True,
            "user_id": user_id,
            "google_proxy_group_id": proxy_group_id,
            "redirect": redirect,
        },
    )

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {"email": google_account}

    r = client.get("/link/google/callback", query_string={"code": test_auth_code})

    assert not add_new_g_acnt_mock.called
    assert r.status_code == 302

    parsed_url = urlparse(r.headers["Location"])
    query_params = parse_qs(parsed_url.query)
    response_redirect = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", "")
    )
    assert "exp" in query_params
    assert query_params["linked_email"][0] == google_account
    assert response_redirect == redirect

    assert not flask.session.get("google_link")
    assert not flask.session.get("user_id")
    assert not flask.session.get("google_proxy_group_id")

    # check that we're adding the G account to the proxy group
    assert add_google_email_to_proxy_group_mock.called
    # TODO check args


def test_google_link_g_account_access_extension(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    add_new_g_acnt_mock,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
):
    """
    Test the link endpoint that gets hit after authN when the provided Google
    account is already linked. This time test if we correctly extend the
    google accounts access.
    """
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    original_expiration = 1000
    test_auth_code = "abc123"
    redirect = "http://localhost"
    google_account = "some-authed-google-account@gmail.com"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={
            "google_link": True,
            "user_id": user_id,
            "google_proxy_group_id": proxy_group_id,
            "redirect": redirect,
        },
    )

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

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {"email": google_account}

    r = client.get("/link/google/callback", query_string={"code": test_auth_code})

    account_in_proxy_group = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id == existing_account.id
        )
        .first()
    )
    assert account_in_proxy_group.proxy_group_id == proxy_group_id

    # check that expiration changed and that it's less than the cfg
    # expires in (since this check will happen a few seconds after
    # it gets set)
    assert account_in_proxy_group.expires != original_expiration
    assert account_in_proxy_group.expires <= (
        int(time.time()) + config["GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN"]
    )

    assert not add_new_g_acnt_mock.called
    assert r.status_code == 302

    parsed_url = urlparse(r.headers["Location"])
    query_params = parse_qs(parsed_url.query)
    response_redirect = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", "")
    )
    assert "exp" in query_params
    assert query_params["linked_email"][0] == google_account
    assert response_redirect == redirect

    assert not flask.session.get("google_link")
    assert not flask.session.get("user_id")
    assert not flask.session.get("google_proxy_group_id")

    assert not add_google_email_to_proxy_group_mock.called


def test_google_link_g_account_exists_linked_to_different_user(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    add_new_g_acnt_mock,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
):
    """
    Test the link endpoint that gets hit after authN when the provided Google
    account is already linked to a different user. We should not attempt to
    create a new user google account and just redirect with
    an error.
    """
    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    test_auth_code = "abc123"
    redirect = "http://localhost"
    google_account = "some-authed-google-account@gmail.com"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={
            "google_link": True,
            "user_id": user_id + 5,  # <- NOT the user whose g acnt exists
            "google_proxy_group_id": proxy_group_id,
            "redirect": redirect,
        },
    )

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {"email": google_account}

    r = client.get("/link/google/callback", query_string={"code": test_auth_code})

    assert not add_new_g_acnt_mock.called

    # make sure we're redirecting with error information
    parsed_url = urlparse(r.headers["Location"])
    query_params = parse_qs(parsed_url.query)
    response_redirect = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", "")
    )
    response_redirect = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", "")
    )
    assert "exp" not in query_params
    assert "linked_email" not in query_params
    assert "error" in query_params
    assert "error_description" in query_params
    assert response_redirect == redirect

    assert not flask.session.get("google_link")
    assert not flask.session.get("user_id")
    assert not flask.session.get("google_proxy_group_id")

    assert not add_google_email_to_proxy_group_mock.called


def test_google_link_no_proxy_group(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    add_new_g_acnt_mock,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
):
    user_id = encoded_creds_jwt["user_id"]

    test_auth_code = "abc123"
    redirect = "http://localhost"
    google_account = "some-authed-google-account@gmail.com"

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={
            "google_link": True,
            "user_id": user_id,
            "google_proxy_group_id": None,  # <- no proxy group
            "redirect": redirect,
        },
    )

    existing_account = UserGoogleAccount(email=google_account, user_id=user_id)
    db_session.add(existing_account)
    db_session.commit()

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    # simulate successfully authed reponse with user email
    google_auth_get_user_info_mock.return_value = {"email": google_account}

    r = client.get("/link/google/callback", query_string={"code": test_auth_code})

    assert not add_new_g_acnt_mock.called

    # make sure we're redirecting with error information
    parsed_url = urlparse(r.headers["Location"])
    query_params = parse_qs(parsed_url.query)
    response_redirect = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", "")
    )
    assert "exp" not in query_params
    assert "linked_email" not in query_params
    assert "error" in query_params
    assert "error_description" in query_params
    assert response_redirect == redirect

    assert not flask.session.get("google_link")
    assert not flask.session.get("user_id")
    assert not flask.session.get("google_proxy_group_id")

    assert not add_google_email_to_proxy_group_mock.called


def test_google_link_redirect_when_google_mocked(
    client, app, encoded_creds_jwt, monkeypatch
):
    """
    Test that when we hit the link endpoint and we're mocking Google login, we
    get redirected to the /link callback.
    """
    monkeypatch.setitem(config, "MOCK_GOOGLE_AUTH", True)
    redirect = "http://localhost"

    r = client.get(
        "/link/google",
        query_string={"redirect": redirect},
        headers={"Authorization": "Bearer " + encoded_creds_jwt.jwt},
    )

    assert r.status_code == 302
    url, query_params = split_url_and_query_params(r.location)
    assert "/link/google/callback" in url
    assert "code" in query_params


def test_google_link_when_google_mocked(
    app,
    client,
    db_session,
    encoded_creds_jwt,
    google_auth_get_user_info_mock,
    add_google_email_to_proxy_group_mock,
    monkeypatch,
):
    """"""
    monkeypatch.setitem(config, "MOCK_GOOGLE_AUTH", True)

    user_id = encoded_creds_jwt["user_id"]
    proxy_group_id = encoded_creds_jwt["proxy_group_id"]

    redirect = "http://localhost"
    google_account = encoded_creds_jwt["username"]

    test_session_jwt = create_session_token(
        app.keypairs[0],
        config.get("SESSION_TIMEOUT"),
        context={
            "google_link": True,
            "user_id": user_id,
            "google_proxy_group_id": proxy_group_id,
            "redirect": redirect,
        },
    )

    # manually set cookie for initial session
    client.set_cookie("localhost", config["SESSION_COOKIE_NAME"], test_session_jwt)

    headers = {"Authorization": "Bearer " + encoded_creds_jwt.jwt}

    r_link = client.get(
        "/link/google/", headers=headers, query_string={"redirect": redirect}
    )

    redirect_location = str(r_link.location).replace(config["BASE_URL"], "")
    # Pass through the Authorization header in the response...
    # In our actual commons, the reverse proxy handles dumping this into the request
    # again. this is ONLY used when MOCK_GOOGLE_AUTH is true (e.g. we're trying to
    # fake a Google login)
    auth_header = r_link.headers.get("Authorization")
    r = client.get(redirect_location, headers={"Authorization": auth_header})

    assert r.status_code == 302
    parsed_url = urlparse(r.headers["Location"])
    query_params = parse_qs(parsed_url.query)
    response_redirect = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", "")
    )
    assert "exp" in query_params
    assert query_params["linked_email"][0] == google_account
    assert response_redirect == redirect

    user_google_account = (
        db_session.query(UserGoogleAccount)
        .filter(
            UserGoogleAccount.email == google_account,
            UserGoogleAccount.user_id == user_id,
        )
        .first()
    )
    assert user_google_account

    assert not flask.session.get("google_link")
    assert not flask.session.get("user_id")
    assert not flask.session.get("google_proxy_group_id")

    assert add_google_email_to_proxy_group_mock.called
