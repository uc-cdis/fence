"""
OIDC specification of authentication request parameter ``display``:

        OPTIONAL. ASCII string value that specifies how the Authorization
        Server displays the authentication and consent user interface pages to
        the End-User. The defined values are:
            page
                The Authorization Server SHOULD display the authentication and
                consent UI consistent with a full User Agent page view. If the
                display parameter is not specified, this is the default display
                mode.
            popup
                The Authorization Server SHOULD display the authentication and
                consent UI consistent with a popup User Agent window. The popup
                User Agent window should be of an appropriate size for a
                login-focused dialog and should not obscure the entire window
                that it is popping up over.
            touch
                The Authorization Server SHOULD display the authentication and
                consent UI consistent with a device that leverages a touch
                interface.
            wap
                The Authorization Server SHOULD display the authentication and
                consent UI consistent with a "feature phone" type display.

        The Authorization Server MAY also attempt to detect the
        capabilities of the User Agent and present an appropriate display.
"""

from tests.utils import oauth2


def test_display_option_page(client, oauth_client):
    """
    Test the very basic requirement that including the ``display`` parameter
    with page option does not cause any errors.
    """
    data = {'display': 'page'}
    auth_response = oauth2.post_authorize(client, oauth_client, data=data, confirm=True)
    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    assert oauth2.code_from_authorize_response(auth_response)


def test_display_option_popup(client, oauth_client):
    """
    Test the very basic requirement that including the ``display`` parameter
    with page option does not cause any errors.
    """
    data = {'display': 'popup'}
    auth_response = oauth2.post_authorize(client, oauth_client, data=data, confirm=True)
    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    assert oauth2.code_from_authorize_response(auth_response)


def test_display_option_touch(client, oauth_client):
    """
    Test the very basic requirement that including the ``display`` parameter
    with page option does not cause any errors.
    """
    data = {'display': 'touch'}
    auth_response = oauth2.post_authorize(client, oauth_client, data=data, confirm=True)
    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    assert oauth2.code_from_authorize_response(auth_response)


def test_display_option_wap(client, oauth_client):
    """
    Test the very basic requirement that including the ``display`` parameter
    with page option does not cause any errors.
    """
    data = {'display': 'wap'}
    auth_response = oauth2.post_authorize(client, oauth_client, data=data, confirm=True)
    assert auth_response.status_code == 302
    assert 'Location' in auth_response.headers
    assert oauth2.code_from_authorize_response(auth_response)
