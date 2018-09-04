"""
OIDC specification of authentication request parameter ``ui_locales``:

    OPTIONAL. End-User's preferred languages and scripts for the user
    interface, represented as a space-separated list of BCP47 [RFC5646]
    language tag values, ordered by preference. For instance, the value "fr-CA
    fr en" represents a preference for French as spoken in Canada, then French
    (without a region designation), followed by English (without a region
    designation). An error SHOULD NOT result if some or all of the requested
    locales are not supported by the OpenID Provider.


Also quoting the specification:

    Note that the minimum level of support required for these parameters is
    simply to have their use not result in errors.
"""


def test_ui_locale_no_errors(oauth_test_client):
    """
    Test the very basic requirement that including the ``ui_locales`` parameter
    does not cause any errors.
    """
    data = {"confirm": "yes", "ui_locales": "fr-CA fr en"}
    auth_response = oauth_test_client.authorize(data=data).response
    assert auth_response.status_code == 200
    assert "redirect" in auth_response.json
