"""
OIDC specification of authentication request parameter ``max_age``:

    OPTIONAL. Maximum Authentication Age. Specifies the allowable elapsed time
    in seconds since the last time the End-User was actively authenticated by
    the OP. If the elapsed time is greater than this value, the OP MUST attempt
    to actively re-authenticate the End-User. (The max_age request parameter
    corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] max_auth_age request
    parameter.) When max_age is used, the ID Token returned MUST include an
    auth_time Claim Value.
"""

from fence.jwt.validate import validate_jwt

from tests.utils import oauth2


def test_reauthenticate_end_user(client, oauth_client):
    data = {'max_age': 0}

    # TODO

    response = oauth2.post_authorize(client, oauth_client, data=data)


def test_id_token_contains_auth_time(client, oauth_client):
    """
    Test that if ``max_age`` is included in the authentication request, then
    the ID token returned contains an ``auth_time`` claim.
    """
    data = {'max_age': 3600}
    token_response = oauth2.get_token_response(
        client, oauth_client, code_request_data=data
    ).json
    id_token = validate_jwt(token_response['id_token'], {'openid'})
    assert 'auth_time' in id_token
