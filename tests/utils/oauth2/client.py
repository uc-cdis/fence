import urllib
from urlparse import url_decode, urlparse


import fence.utils


class AuthorizeResponse(object):
    """
    Attributes:
        location (str): location for redirect
        code (str): authorization code obtained, used to get token
    """

    def __init__(self, response):
        if response.status_code == 302:
            assert 'Location' in response.headers
            self.location = response.headers['Location']
        else:
            assert 'redirect' in response.json
            self.location = response.json['redirect']
        location_qs_args = dict(url_decode(urlparse(self.location).query))
        assert 'code' in location_qs_args
        self.code = location_qs_args.get('code')


class TokenResponse(object):
    """
    Note that the ID token is not part of the OAuth2 spec, but is part of the
    OIDC core spec and therefore this implementation.

    Attributes:
        access_token (dict)
        refresh_token (dict)
        id_token (dict)
    """

    def __init__(self, response, do_asserts=True):
        if do_asserts:
            assert response.status_code == 200, response.json
            assert 'access_token' in response.json
            assert 'refresh_token' in response.json
            assert 'id_token' in response.json
        self.access_token = response.json['access_token']
        self.refresh_token = response.json['refresh_token']
        self.id_token = response.json['id_token']


class OAuth2TestClient(object):
    """
    A client for testing which handles basic OAuth2 operations.

    NOTE: the ``AuthorizeResponse`` and ``TokenResponse`` classes both do basic
    testing on the responses they receive, so those do not need to be written
    into every test using this test client.

    Attributes:
        _auth_header (dict)
        _client (werkzeug.test.Client)
        authorize_response (AuthorizeResponse)
        client_id (str): OAuth client ID
        client_secret (str): OAuth client secret
        refresh_response (TokenResponse)
        token_response (TokenResponse)
        url (str): OAuth client redirect URL

    Example:

    .. code-block:: python

        @pytest.fixture(scope='function')
        def oauth_test_client(client, oauth_client):
            return OAuth2TestClient(client, oauth_client)

        def test_post_token(oauth_test_client):
            oauth_test_client.authorize()
            code = oauth_test_client.authorize_response
            oauth_test_client.token()
            access_token = oauth_test_client.token_response.access_token
            # etc.
    """

    PATH_AUTHORIZE = '/oauth2/authorize'
    PATH_TOKEN = '/oauth2/token'
    PATH_REFRESH = '/oauth2/token'
    PATH_REVOKE = '/oauth2/revoke'

    def __init__(self, flask_client, oauth_client, confidential=True):
        """
        Args:
            flask_client (werkzeug.test.Client): test client for requests
            oauth_client (addict.Dict): information about oauth client
        """
        self._client = flask_client
        self.client_id = oauth_client.client_id
        self.url = oauth_client.url
        if confidential:
            self.client_secret = oauth_client.client_secret
            self._auth_header = fence.utils.create_basic_header(
                self.client_id, self.client_secret
            )
        else:
            self.client_secret = None
            self._auth_header = None

        # This will be set to the authorize response from the authorize method.
        self.authorize_response = None
        # This will be set to the token response from the token method.
        self.token_response = None
        # This will be set to the token response from the refresh method.
        self.refresh_response = None

    def _path_for_authorize(self, params=None):
        """
        Return the path for the authorization endpoint.

        Args:
            params (dict): query string parameters

        Return:
            str
        """
        return self.PATH_AUTHORIZE + '?' + urllib.urlencode(query=params)

    def authorize(self, method='POST', data=None):
        """
        Call the authorize endpoint.

        Args:
            method (str): HTTP method (GET or POST)
            data (dict): arguments to send in request (either QS or form)

        Return:
            AuthorizeResponse
        """
        data = data or {}
        default_data = {
            'client_id': self.client_id,
            'redirect_uri': self.url,
            'response_type': 'code',
            'scope': 'openid user',
            'state': fence.utils.random_str(10)
        }
        default_data.update(data)
        data = default_data
        if isinstance(data['scope'], list):
            data['scope'] = ' '.join(data['scope'])

        if self.method == 'GET':
            response = self._client.open(
                method=method,
                path=self._path_for_authorize(params=data),
                headers=self._auth_header,
            )
        elif self.method == 'POST':
            response = self._client.open(
                method=method,
                path=self._path_for_authorize(),
                headers=self._auth_header,
                data=data,
            )

        # Check the response code for success.
        # NOTE: GET should be returning a redirect (302), and POST should be
        # returning a 200 with the redirect in JSON.
        if self.method == 'GET':
            assert response.status_code == 302
        elif self.method == 'POST':
            assert response.status_code == 200

        self.authorize_response = AuthorizeResponse(response)

        # Check that the redirect does go to the correct URL.
        assert self.authorize_response.location.startswith(self.url)

        return self.authorize_response

    def token(self, code=None, do_asserts=True):
        if not code and not self.authorize_response:
            raise ValueError('no code provided')
        code = code or self.authorize_response.code
        data = {
            'client_id': self.client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.url,
        }
        if self.client_secret:
            data['client_secret'] = self.client_secret
        response = self._client.post(
            self.PATH_TOKEN, headers=self._auth_header, data=data
        )
        self.token_response = TokenResponse(response, do_asserts=do_asserts)
        return self.token_response

    def refresh(self, refresh_token=None, do_asserts=True):
        if not refresh_token and not self.token_response:
            raise ValueError('no refresh token provided')
        refresh_token = refresh_token or self.token_response.refresh_token
        data = {
            'client_id': self.client_id,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }
        if self.client_secret:
            data['client_secret'] = self.client_secret
        response = self._client.post(
            self.PATH_REFRESH,
            headers=self._auth_header,
            data=data,
        )
        self.refresh_response = TokenResponse(response, do_asserts=True)
        return self.refresh_response

    def revoke(self, refresh_token=None):
        if not refresh_token and not self.token_response:
            raise ValueError('no refresh token provided')
        refresh_token = refresh_token or self.token_response.refresh_token
        response = self._client.post(
            self.PATH_REVOKE,
            headers=self._auth_header,
            data={'token': refresh_token},
        )
        assert response.status_code == 204
