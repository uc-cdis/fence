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
import pytest

from urllib.parse import urlparse, parse_qs

from fence.jwt.validate import validate_jwt
from tests.utils import oauth2
from fence.config import config


@pytest.mark.skip(
    reason="We are NOT COMPLIANT for this OPTIONAL param (id_token_hint) yet."
)
def test_id_token_hint_empty(client, oauth_client):
    """
    Test ``id_token_hint`` parameter when it's empty.

    "If the End-User identified by the ID Token is logged in or is logged in
    by the request, then the Authorization Server returns a positive response;
    otherwise, it SHOULD return an error"

    No end user in hint, so return an error
    """
    data = {"id_token_hint": ""}

    auth_response = oauth2.post_authorize(client, oauth_client, data=data, confirm=True)
    assert auth_response.status_code == 302
    assert "Location" in auth_response.headers
    query_params = parse_qs(urlparse(auth_response.headers["Location"]).query)
    assert "error" in query_params
    assert query_params["error"][0] == "access_denied"


@pytest.mark.skip(
    reason="We are NOT COMPLIANT for this OPTIONAL param (id_token_hint) yet."
)
def test_id_token_hint(client, oauth_client):
    """
    Test ``id_token_hint`` parameter when hinted user is logged in
    """
    token_response = oauth2.get_token_response(client, oauth_client).json
    id_token = validate_jwt(token_response["id_token"], {"openid"})

    # Now use that id_token as a hint to the authorize endpoint
    data = {"id_token_hint": str(id_token)}

    new_token_response = oauth2.get_token_response(
        client, oauth_client, code_request_data=data
    )
    new_id_token = validate_jwt(token_response["id_token"], {"openid"})
    assert new_token_response.status_code == 200
    assert new_id_token["sub"] == id_token["sub"]


@pytest.mark.skip(
    reason="We are NOT COMPLIANT for this OPTIONAL param (id_token_hint) yet."
)
def test_id_token_hint_not_logged_in(app, client, oauth_client, monkeypatch):
    """
    Test ``id_token_hint`` parameter when hinted user is not logged in.
    TODO: This should attempt to log the user in
    """
    # test user is logged in right now
    token_response = oauth2.get_token_response(client, oauth_client).json
    id_token = validate_jwt(token_response["id_token"], {"openid"})

    # don't mock auth so there isn't a logged in user any more
    monkeypatch.setitem(config, "MOCK_AUTH", False)

    # Now use that id_token as a hint to the authorize endpoint
    data = {"id_token_hint": str(id_token)}

    auth_response = oauth2.post_authorize(client, oauth_client, data=data, confirm=True)
    assert auth_response.status_code == 302
    assert "Location" in auth_response.headers
    query_params = parse_qs(urlparse(auth_response.headers["Location"]).query)
    assert "error" in query_params
    assert query_params["error"][0] == "access_denied"
