import pytest

from tests.utils import oauth2


@pytest.fixture(scope='function')
def token_response_json(client, oauth_client):
    """
    Define a fixture for this module for a successful token response.
    """
    return oauth2.get_token_response(client, oauth_client).json
