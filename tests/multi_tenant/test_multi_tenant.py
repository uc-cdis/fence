"""
It is very recommended to look at the multi-tenant flow diagram before looking
at this code; otherwise it is likely for none of this to make any sense.
"""

import urllib
import urlparse
# in python3:
# urllib.parse

import fence

from tests.utils import oauth2
from tests.utils import remove_qs


def test_redirect_from_oauth(fence_client_app, oauth_client):
    """
    Test that the ``/oauth2/authorize`` endpoint on the client redirects to the
    ``/login/fence`` endpoint, also on the client.
    """
    with fence_client_app.test_client() as test_client:
        data = {
            'client_id': oauth_client.client_id,
            'redirect_uri': oauth_client.url,
            'response_type': 'code',
            'scope': 'openid user',
            'state': fence.utils.random_str(10),
            'confirm': 'yes',
        }
        response_oauth_authorize = test_client.post('/oauth2/authorize', data=data)
        assert response_oauth_authorize.status_code == 302
        assert '/login/fence' in response_oauth_authorize.location


def test_login(
        app, fence_client_app, fence_oauth_client, fence_oauth_client_url,
        mock_get, example_keys_response, monkeypatch):
    """
    Test that:
        1. the ``/login/fence`` client endpoint redirects to the
          ``/oauth2/authorize`` endpoint on the IDP fence,
        2. POST-ing to ``/oauth2/authorize`` on the IDP fence redirects to
          the configured client URL with the code in the query string
          arguments
    """
    # Disable the keys refreshing since requests will not work with the client
    # app.
    monkeypatch.setattr(
        'authutils.token.keys.refresh_jwt_public_keys',
        lambda: None
    )

    with fence_client_app.test_client() as fence_client_client:
        # Part 1.
        redirect_url_quote = urllib.quote('/login/fence/login')
        path = '/login/fence?redirect_uri={}'.format(redirect_url_quote)
        response_login_fence = fence_client_client.get(path)
        # This should be pointing at ``/oauth2/authorize`` of the IDP fence.
        assert '/oauth2/authorize' in response_login_fence.location

    with app.test_client() as client:
        # Part 2.
        # Remove the QS from the URL so we can use POST instead.
        url = remove_qs(response_login_fence.location)
        # should now have ``url == 'http://localhost:50000/oauth2/authorize``.
        # de-listify the QS arguments
        authorize_params = urlparse.parse_qs(
            urlparse.urlparse(response_login_fence.location).query
        )
        authorize_params = {k: v[0] for k, v in authorize_params.iteritems()}
        authorize_params['confirm'] = 'yes'
        headers = oauth2.create_basic_header_for_client(fence_oauth_client)
        # Normally this would just redirect back to the configured client URL
        # with the code as a query string argument.
        authorize_response = client.post(
            url, headers=headers, data=authorize_params
        )
        assert authorize_response.status_code == 200
        assert 'redirect' in authorize_response.json
        authorize_redirect = authorize_response.json['redirect']
        assert remove_qs(authorize_redirect) == fence_oauth_client_url
        assert 'code' in authorize_redirect
