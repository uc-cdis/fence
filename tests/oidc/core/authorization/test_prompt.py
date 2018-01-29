"""
OIDC specification of authentication request parameter ``prompt``:

    OPTIONAL. Space delimited, case sensitive list of ASCII string values that
    specifies whether the Authorization Server prompts the End-User for
    reauthentication and consent. The defined values are:
        none
            The Authorization Server MUST NOT display any authentication or
            consent user interface pages. An error is returned if an End-User
            is not already authenticated or the Client does not have
            pre-configured consent for the requested Claims or does not fulfill
            other conditions for processing the request. The error code will
            typically be ``login_required``, ``interaction_required``, or
            another code defined in Section 3.1.2.6. This can be used as a
            method to check for existing authentication and/or consent.
        login
            The Authorization Server SHOULD prompt the End-User for
            reauthentication. If it cannot reauthenticate the End-User, it MUST
            return an error, typically ``login_required``.
        consent
            The Authorization Server SHOULD prompt the End-User for consent
            before returning information to the Client. If it cannot obtain
            consent, it MUST return an error, typically ``consent_required``.
        select_account
            The Authorization Server SHOULD prompt the End-User to select a
            user account. This enables an End-User who has multiple accounts at
            the Authorization Server to select amongst the multiple accounts
            that they might have current sessions for. If it cannot obtain an
            account selection choice made by the End-User, it MUST return an
            error, typically account_selection_required.
"""

from tests.utils import oauth2


def test_no_prompt_provided(client, oauth_client):
    """
    ``prompt`` is optional; test that omitting it is fine.
    """
    response = oauth2.post_authorize(client, oauth_client)
    # TODO make sure no consent screen/page appears
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


def test_prompt_none_logged_in_client_cfg(client, oauth_client):
    """
    Test ``prompt=none`` when user is authN'd and client
    has pre-configured consent for the requested Claims. This is the
    only case where a successful response occurs.
    """
    data = {'prompt': 'none'}

    response = oauth2.post_authorize(client, oauth_client, data=data)
    # TODO make sure no consent screen/page appears
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


def test_prompt_none_not_logged_in_client_cfg(client, oauth_client):
    """
    Test ``prompt=none`` when user is not authN'd and client
    has pre-configured consent for the requested Claims.
    """
    data = {'prompt': 'none'}

    # TODO make user not logged in

    auth_response = oauth2.post_authorize(client, oauth_client, data=data)
    # TODO make sure no consent screen/page appears
    assert auth_response.status_code != 302
    assert 'error' in auth_response.json, auth_response.json
    assert auth_response.json['error'] in ['login_required', 'interaction_required']


def test_prompt_none_not_logged_in_client_not_cfg(client, oauth_client):
    """
    Test ``prompt=none`` when user is not authN'd and client does not
    have pre-configured consent for the requested Claims.
    """
    data = {'prompt': 'none'}

    # TODO make user not logged in

    auth_response = oauth2.post_authorize(client, oauth_client, data=data)
    # TODO make sure no consent screen/page appears
    assert auth_response.status_code != 302
    assert 'error' in auth_response.json, auth_response.json
    assert auth_response.json['error'] in ['login_required', 'interaction_required']


def test_prompt_none_logged_in_client_not_cfg(client, oauth_client):
    """
    Test ``prompt=none`` when user is authN'd and client does not
    have pre-configured consent for the requested Claims.
    """
    data = {'prompt': 'none'}

    # TODO make user not logged in

    auth_response = oauth2.post_authorize(client, oauth_client, data=data)
    # TODO make sure no consent screen/page appears
    assert auth_response.status_code != 302
    assert 'error' in auth_response.json, auth_response.json
    assert auth_response.json['error'] in ['login_required', 'interaction_required']


def test_prompt_login(client, oauth_client):
    """
    Test ``prompt=login`` when user re-AuthN's.
    """
    data = {'prompt': 'login'}

    # TODO

    response = oauth2.post_authorize(client, oauth_client)
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


def test_prompt_login_no_authn(client, oauth_client):
    """
    Test ``prompt=login`` when unable to re-AuthN.
    """
    data = {'prompt': 'login'}

    auth_response = oauth2.post_authorize(client, oauth_client, data=data)
    assert auth_response.status_code != 302
    assert 'error' in auth_response.json, auth_response.json
    assert auth_response.json['error'] == 'login_required'


def test_prompt_consent(client, oauth_client):
    """
    Test ``prompt=consent`` when user approves.
    """
    data = {'prompt': 'consent'}

    # TODO

    response = oauth2.post_authorize(client, oauth_client)
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


def test_prompt_login_no_consent(client, oauth_client):
    """
    Test ``prompt=login`` when user does not consent.
    """
    data = {'prompt': 'login'}

    auth_response = oauth2.post_authorize(client, oauth_client, data=data)
    assert auth_response.status_code != 302
    assert 'error' in auth_response.json, auth_response.json
    assert auth_response.json['error'] == 'consent_required'


def test_prompt_select_account(client, oauth_client):
    """
    Test ``prompt=select_account`` when user chooses an account.
    """
    data = {'prompt': 'select_account'}

    # TODO

    response = oauth2.post_authorize(client, oauth_client)
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


def test_prompt_select_account_no_choice(client, oauth_client):
    """
    Test ``prompt=select_account`` when choice cannot be obtained.
    """
    data = {'prompt': 'select_account'}

    auth_response = oauth2.post_authorize(client, oauth_client, data=data)
    assert auth_response.status_code != 302
    assert 'error' in auth_response.json, auth_response.json
    assert auth_response.json['error'] == 'account_selection_required'

