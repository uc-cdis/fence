import pytest

from tests.utils import oauth2


@pytest.fixture(scope='function')
def token_response_json(client, oauth_client):
    """
    Define a fixture for this module for a successful token response.
    """
    return oauth2.get_token_response(client, oauth_client).json


@pytest.fixture(scope='function')
def id_token(token_response_json):
    """
    Return just an ID token obtained from ``/oauth2/token``.
    """
    return token_response_json['id_token']
