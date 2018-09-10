"""
Test the OP validation of the token request.

Spec from OIDC 3.1.3.2:

    The Authorization Server MUST validate the Token Request as follows:

    - Authenticate the Client if it was issued Client Credentials or if it uses
      another Client Authentication method, per Section 9.
    - Ensure the Authorization Code was issued to the authenticated Client.
    - Verify that the Authorization Code is valid.
    - If possible, verify that the Authorization Code has not been previously
      used.
    - Ensure that the redirect_uri parameter value is identical to the
      redirect_uri parameter value that was included in the initial
      Authorization Request. If the redirect_uri parameter value is not present
      when there is only one registered redirect_uri value, the Authorization
      Server MAY return an error (since the Client should have included the
      parameter) or MAY proceed without an error (since OAuth 2.0 permits the
      parameter to be omitted in this case).
    - Verify that the Authorization Code used was issued in response to an
      OpenID Connect Authentication Request (so that an ID Token will be
      returned from the Token Endpoint).

Tests for client authentication are in
``tests/oidc/core/token/test_client_authentication.py``.

The rest of these points have tests below.
"""

from authlib.common.security import generate_token


def test_reuse_code_invalid(oauth_test_client):
    """
    Test that an authorization code returned from the authorization endpoint
    can be used only once, and after that its attempted usage will return an
    ``invalid_request`` error.
    """
    code = oauth_test_client.authorize(data={"confirm": "yes"}).code
    # Test that the first time using the code is fine.
    oauth_test_client.token(code=code)
    # Test that the second time using the code breaks.
    oauth_test_client.token(code=code, do_asserts=False)
    response = oauth_test_client.token_response.response
    assert response.status_code == 400
    assert "error" in response.json
    assert response.json["error"] == "invalid_request"


def test_different_client_invalid(oauth_test_client, oauth_test_client_B):
    """
    Test that one client cannot use an authorization code which was issued to a
    different client, and the request fails with ``invalid_request``.
    """
    code = oauth_test_client.authorize(data={"confirm": "yes"}).code
    # Have client B send the code to the token endpoint.
    response = oauth_test_client_B.token(code=code, do_asserts=False).response
    assert response.status_code == 400
    assert "error" in response.json
    assert response.json["error"] == "invalid_request"


def test_invalid_code(oauth_test_client):
    """
    Test that a client can't just send in a garbage code.
    """
    code = generate_token(50)
    response = oauth_test_client.token(code=code, do_asserts=False).response
    assert response.status_code == 400
    assert "error" in response.json
    assert response.json["error"] == "invalid_request"


def test_invalid_redirect_uri(oauth_test_client):
    """
    Test that if the token request has a different redirect_uri than the one
    the client is suppsed to be using that an error is raised, with the
    ``invalid_request`` code.
    """
    oauth_test_client.authorize(data={"confirm": "yes"})
    data = {"redirect_uri": oauth_test_client.url + "/some-garbage"}
    response = oauth_test_client.token(data=data, do_asserts=False).response
    assert response.status_code == 400
    assert "error" in response.json
    assert response.json["error"] == "invalid_request"


def test_no_redirect_uri(client, oauth_test_client):
    """
    Test that if the token request has no ``redirect_uri`` that an error is
    raised, with the ``invalid_request`` code.
    """
    code = oauth_test_client.authorize(data={"confirm": "yes"}).code
    headers = oauth_test_client._auth_header
    # Note no ``redirect_uri`` in the data.
    data = {
        "client_id": oauth_test_client.client_id,
        "client_secret": oauth_test_client.client_secret,
        "code": code,
        "grant_type": "authorization_code",
    }
    token_response = client.post(
        oauth_test_client.PATH_TOKEN, headers=headers, data=data
    )
    assert token_response.status_code == 400
    assert "error" in token_response.json
    assert token_response.json["error"] == "invalid_request"
