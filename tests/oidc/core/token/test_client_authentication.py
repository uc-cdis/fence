"""
For the token request, if the client is confidential, it must authenticate to
the token endpoint using its authentication method.
"""

from tests.utils import oauth2


def test_confidential_client_valid(client, oauth_client):
    """
    Test that a confidential client including a basic authorization header in
    the request containing its secret is successfully issued a token.
    """
    token_response = oauth2.get_token_response(client, oauth_client)
    # This function does the asserts.
    oauth2.check_token_response(token_response)


def test_confidential_client_invalid(client, oauth_client):
    """
    Test that a confidential client *not* including an authorization header in
    the request is rejected and produces the error code
    ``unauthorized_client``.
    """
    code = oauth2.get_access_code(client, oauth_client)
    data = {
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': oauth_client.url,
    }
    # Note the empty headers: ``headers={}``.
    token_response = client.post('/oauth2/token', headers={}, data=data)
    assert token_response.status_code == 400, token_response.json
    assert 'error' in token_response.json, token_response.json
    assert token_response.json['error'] == 'unauthorized_client'
