"""
OIDC specification of authentication request parameter ``acr_values``:

    OPTIONAL. Requested Authentication Context Class Reference values.
    Space-separated string that specifies the ``acr`` values that the
    Authorization Server is being requested to use for processing this
    Authentication Request, with the values appearing in order of preference.
    The Authentication Context Class satisfied by the authentication performed
    is returned as the ``acr`` Claim Value, as specified in Section 2. The
    ``acr`` Claim is requested as a Voluntary Claim by this parameter.
"""
import pytest

from fence.jwt.validate import validate_jwt

from tests.utils import oauth2


@pytest.mark.skip(reason="We are NOT COMPLIANT for this OPTIONAL param (acr) yet.")
def test_acr_values(client, oauth_client):
    """
    Test the very basic requirement that including the ``acr_values`` parameter
    does not cause any errors and the acr claim is represented in the resulting token.
    """
    data = {"acr_values": ""}
    token_response = oauth2.get_token_response(
        client, oauth_client, code_request_data=data
    ).json
    id_token = validate_jwt(token_response["id_token"], {"openid"})
    assert "acr" in id_token
