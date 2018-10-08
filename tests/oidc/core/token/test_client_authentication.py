"""
For the token request, if the client is confidential, it must authenticate to
the token endpoint using its authentication method.
"""


def test_confidential_client_valid(oauth_test_client):
    """
    Test that a confidential client including a basic authorization header in
    the request containing its secret is successfully issued a token.
    """
    oauth_test_client.authorize(data={"confirm": "yes"})
    oauth_test_client.token()


def test_confidential_client_invalid(oauth_test_client, monkeypatch):
    """
    Test that a confidential client *not* including an authorization header in
    the request is rejected and produces the error code
    ``invalid_client``.
    """
    # Disable the basic auth header.
    monkeypatch.setattr(oauth_test_client, "_auth_header", {})
    oauth_test_client.authorize(data={"confirm": "yes"})
    token_response = oauth_test_client.token(
        do_asserts=False, include_auth=False
    ).response
    assert token_response.status_code == 401, token_response.json
    assert "error" in token_response.json, token_response.json
    assert token_response.json["error"] == "invalid_client"
