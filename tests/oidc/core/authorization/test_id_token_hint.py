"""
OIDC specification of authentication request parameter ``id_token_hint``:

    OPTIONAL. ID Token previously issued by the Authorization Server being
    passed as a hint about the End-User's current or past authenticated session
    with the Client. If the End-User identified by the ID Token is logged in or
    is logged in by the request, then the Authorization Server returns a
    positive response; otherwise, it SHOULD return an error, such as
    login_required. When possible, an id_token_hint SHOULD be present when
    prompt=none is used and an invalid_request error MAY be returned if it
    is not; however, the server SHOULD respond successfully when possible,
    even if it is not present. The Authorization Server need not be listed
    as an audience of the ID Token when it is used as an id_token_hint value.

    If the ID Token received by the RP from the OP is encrypted, to use it as
    an id_token_hint, the Client MUST decrypt the signed ID Token contained
    within the encrypted ID Token. The Client MAY re-encrypt the signed ID
    token to the Authentication Server using a key that enables the server to
    decrypt the ID Token, and use the re-encrypted ID token as the
    id_token_hint value.
"""

from fence.jwt.validate import validate_jwt
from tests.utils import oauth2


def test_id_token_hint_empty(client, oauth_client):
    """
    Test ``id_token_hint`` parameter when it's empty
    """
    data = {'id_token_hint': ''}

    auth_response = oauth2.post_authorize(client, oauth_client, data=data)
    assert auth_response.status_code != 302
    assert 'error' in auth_response.json, auth_response.json
    assert auth_response.json['error'] == 'login_required'


def test_id_token_hint(client, oauth_client):
    """
    Test ``id_token_hint`` parameter when hinted user logs in
    """
    token_response = oauth2.get_token_response(
        client, oauth_client).json
    id_token = validate_jwt(token_response['id_token'], {'openid'})

    # Now use that id_token as a hint to the authorize endpoint
    data = {'id_token_hint': str(id_token)}

    new_token_response = oauth2.get_token_response(
        client, oauth_client, code_request_data=data).json
    new_id_token = validate_jwt(token_response['id_token'], {'openid'})
    assert new_token_response.status_code == 200
    assert new_id_token['sub'] == id_token['sub']


def test_id_token_hint_not_logged_in(client, oauth_client):
    """
    Test ``id_token_hint`` parameter when hinted user is not logged in
    """
    token_response = oauth2.get_token_response(
        client, oauth_client).json
    id_token = validate_jwt(token_response['id_token'], {'openid'})

    # TODO somehow make user not logged in

    # Now use that id_token as a hint to the authorize endpoint
    data = {'id_token_hint': str(id_token)}

    response = oauth2.get_token_response(
        client, oauth_client, code_request_data=data).json
    assert "id_token" not in response
    assert response.status_code != 200
    assert 'error' in response
    assert response['error'] == 'login_required'
