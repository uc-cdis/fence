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


def test_id_token_contains_auth_time():
    """
    Test that if ``max_age`` is included in the authentication request, then
    the ID token returned contains an ``auth_time`` claim.
    """
    # TODO
    pass
