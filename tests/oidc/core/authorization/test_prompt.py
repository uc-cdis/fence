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
import pytest

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

try:
    # Python 3
    from urllib.parse import urlparse, parse_qs
except ImportError:
    # Python 2
    from urlparse import urlparse, parse_qs

from fence.errors import Unauthorized

from tests.utils import oauth2


def test_no_prompt_provided(client, oauth_client):
    """
    ``prompt`` is optional; test that omitting it is fine.
    """
    with patch('flask.render_template') as render_mock:
        oauth2.get_authorize(client, oauth_client)
        # make sure consent screen/page appears
        assert render_mock.called is True

    # Now use fake user consent confirmation
    response = oauth2.get_authorize(client, oauth_client, confirm=True)

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

    with patch('flask.render_template') as render_mock:
        oauth2.get_authorize(client, oauth_client, data=data)
        # make sure no consent screen/page appears
        assert render_mock.called is False

    # Now use fake user consent confirmation
    response = oauth2.get_authorize(client, oauth_client, data=data, confirm=True)

    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


def test_prompt_none_not_logged_in_client_cfg(app, client, oauth_client, monkeypatch):
    """
    Test ``prompt=none`` when user is not authN'd and client
    has pre-configured consent for the requested Claims.
    """
    data = {'prompt': 'none'}

    # don't mock auth so there isn't a logged in user
    monkeypatch.setitem(app.config, 'MOCK_AUTH', False)

    with patch('flask.render_template') as render_mock:
        oauth2.get_authorize(client, oauth_client, data=data)
        # make sure no consent screen/page appears
        assert render_mock.called is False

    # Now use fake user consent confirmation
    auth_response = oauth2.get_authorize(client, oauth_client, data=data, confirm=True)

    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    query_params = parse_qs(urlparse(auth_response.headers['Location']).query)
    assert 'error' in query_params

    # for some reason, query_params for error come back as a list,
    # even though its just a string in response. So get the first (and
    # only) item
    assert query_params['error'][0] == 'access_denied'


def test_prompt_none_not_logged_in_client_not_cfg(app, client, oauth_client, monkeypatch):
    """
    Test ``prompt=none`` when user is not authN'd and client does not
    have pre-configured consent for the requested Claims.
    """
    data = {'prompt': 'none'}

    # TODO make client not have pre-cfg consent

    # don't mock auth so there isn't a logged in user
    monkeypatch.setitem(app.config, 'MOCK_AUTH', False)

    with patch('flask.render_template') as render_mock:
        oauth2.get_authorize(client, oauth_client, data=data)
        # make sure no consent screen/page appears
        assert render_mock.called is False

    # Now use fake user consent confirmation
    auth_response = oauth2.get_authorize(client, oauth_client, data=data, confirm=True)

    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    query_params = parse_qs(urlparse(auth_response.headers['Location']).query)
    assert 'error' in query_params
    assert query_params['error'][0] == 'access_denied'


def test_prompt_none_logged_in_client_not_cfg(client, oauth_client):
    """
    Test ``prompt=none`` when user is authN'd and client does not
    have pre-configured consent for the requested Claims.
    """
    data = {'prompt': 'none'}

    # TODO make client not have pre-cfg consent

    with patch('flask.render_template') as render_mock:
        oauth2.get_authorize(client, oauth_client, data=data)
        # make sure no consent screen/page appears
        assert render_mock.called is False

    # Now use fake user consent confirmation
    auth_response = oauth2.get_authorize(client, oauth_client, data=data, confirm=True)

    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    query_params = parse_qs(urlparse(auth_response.headers['Location']).query)
    assert 'error' in query_params
    assert query_params['error'][0] == 'access_denied'


def test_prompt_login(client, oauth_client):
    """
    Test ``prompt=login`` when user re-AuthN's.
    """
    data = {'prompt': 'login'}

    with patch('fence.blueprints.oauth2.handle_login') as handle_login_mock:
        response = oauth2.get_authorize(client, oauth_client, data=data)
        assert handle_login_mock.called is True

    # Now use fake user consent confirmation
    response = oauth2.get_authorize(client, oauth_client, data=data, confirm=True)

    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


def test_prompt_login_no_authn(client, oauth_client):
    """
    Test ``prompt=login`` when unable to re-AuthN.
    """
    data = {'prompt': 'login'}

    with patch('fence.blueprints.oauth2.handle_login') as handle_login_mock:
        handle_login_mock.side_effect = Unauthorized('couldnt authN')
        auth_response = oauth2.get_authorize(client, oauth_client, data=data)

        assert auth_response.status_code == 302
        assert 'Location' in auth_response.headers
        query_params = parse_qs(urlparse(auth_response.headers['Location']).query)
        assert 'error' in query_params
        assert query_params['error'][0] == 'access_denied'


def test_prompt_consent_no_login(app, client, oauth_client, monkeypatch):
    """
    Test ``prompt=consent`` when user is not logged in, should raise error.
    """
    data = {'prompt': 'consent'}

    # don't mock auth so there isn't a logged in user
    monkeypatch.setitem(app.config, 'MOCK_AUTH', False)

    response = oauth2.get_authorize(client, oauth_client, data=data)
    assert response.status_code == 302
    assert 'Location' in response.headers
    query_params = parse_qs(urlparse(response.headers['Location']).query)
    assert 'error' in query_params
    assert query_params['error'][0] == 'access_denied'


def test_prompt_consent(app, client, oauth_client):
    """
    Test ``prompt=consent`` when user approves. Should display consent
    screen and then have correct response.
    """
    data = {'prompt': 'consent'}

    with patch('flask.render_template') as render_mock:
        oauth2.get_authorize(client, oauth_client)
        # make sure consent screen/page appears
        assert render_mock.called is True

    # Now use fake user consent confirmation
    response = oauth2.get_authorize(client, oauth_client, data=data, confirm=True)
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


def test_prompt_login_no_consent(app, client, oauth_client):
    """
    Test ``prompt=login`` when user does not consent. Should still show
    consent screen but then return with error.
    """
    data = {'prompt': 'login'}

    with patch('flask.render_template') as render_mock:
        oauth2.get_authorize(client, oauth_client, data=data)
        # make sure consent screen/page appears
        assert render_mock.called is True

    # Now use fake user consent confirmation
    auth_response = oauth2.get_authorize(client, oauth_client, data=data, confirm=False)
    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    query_params = parse_qs(urlparse(auth_response.headers['Location']).query)
    assert 'error' in query_params
    assert query_params['error'][0] == 'access_denied'


@pytest.mark.skip(reason="we don't support choosing an account at this point "
                         "since users can only have one account")
def test_prompt_select_account(client, oauth_client):
    """
    Test ``prompt=select_account`` when user chooses an account.
    """
    data = {'prompt': 'select_account'}

    # TODO check that account selection screen shows up

    response = oauth2.get_authorize(client, oauth_client, data=data)
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert oauth2.code_from_authorize_response(response)


@pytest.mark.skip(reason="we don't support choosing an account at this point "
                         "since users can only have one account")
def test_prompt_select_account_no_choice(client, oauth_client):
    """
    Test ``prompt=select_account`` when choice cannot be obtained.
    """
    data = {'prompt': 'select_account'}

    # TODO check that account selection screen shows up
    # TODO force result to be no choice from selection options

    auth_response = oauth2.get_authorize(client, oauth_client, data=data)
    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    query_params = parse_qs(urlparse(auth_response.headers['Location']).query)
    assert 'error' in query_params
    assert query_params['error'][0] == 'account_selection_required'
