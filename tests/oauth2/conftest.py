import pytest

import tests.utils.oauth2


@pytest.fixture(scope='function')
def token_response(client, oauth_client):
    """
    Return the token response from the end of the OAuth procedure from
    ``/oauth2/token``.
    """
    return tests.utils.oauth2.get_token_response(client, oauth_client)


@pytest.fixture(scope='function')
def access_token(client, oauth_client):
    """
    Return just an access token obtained from ``/oauth2/token``.
    """
    token_response = tests.utils.oauth2.get_token_response(
        client, oauth_client
    )
    return token_response.json['access_token']


@pytest.fixture(scope='function')
def refresh_token(client, oauth_client):
    """
    Return just a refresh token obtained from ``/oauth2/token``.
    """
    token_response = tests.utils.oauth2.get_token_response(
        client, oauth_client
    )
    return token_response.json['refresh_token']
