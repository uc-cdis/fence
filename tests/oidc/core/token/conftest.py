import pytest


@pytest.fixture(scope="function")
def token_response(oauth_test_client):
    """
    Return a successful token response.
    """
    oauth_test_client.authorize(data={"confirm": "yes"})
    return oauth_test_client.token().response


@pytest.fixture(scope="function")
def token_response_json(token_response):
    """
    Return the JSON from a successful token response.
    """
    return token_response.json


@pytest.fixture(scope="function")
def id_token(token_response_json):
    """
    Return just an ID token obtained from ``/oauth2/token``.
    """
    return token_response_json["id_token"]
