import urllib.request, urllib.parse, urllib.error
from urllib.parse import parse_qs, urlparse

import fence.utils

import tests.utils.oauth2


class AuthorizeResponse(object):
    """
    Attributes:
        location (str): location for redirect
        code (str): authorization code obtained, used to get token
    """

    def __init__(self, response):
        self.response = response
        self.location = None
        try:
            if response.status_code == 302:
                self.location = response.headers["Location"]
            else:
                if getattr(response, "json"):
                    self.location = response.json["redirect"]
        except (KeyError, ValueError):
            self.location = None
        try:
            location_qs_args = dict(parse_qs(urlparse(self.location).query))
            self.code = location_qs_args.get("code")
        except AttributeError:
            self.code = None

    def do_asserts(self, expected_code):
        assert self.response.status_code == expected_code
        if self.response.status_code == 302:
            assert "Location" in self.response.headers
        else:
            assert "redirect" in self.response.json
        assert self.code


class TokenResponse(object):
    """
    Note that the ID token is not part of the OAuth2 spec, but is part of the
    OIDC core spec and therefore this implementation.

    Attributes:
        access_token (dict)
        refresh_token (dict)
        id_token (dict)
    """

    def __init__(self, response):
        self.response = response
        try:
            self.access_token = response.json.get("access_token")
            self.refresh_token = response.json.get("refresh_token")
            self.id_token = response.json.get("id_token")
        except (ValueError, AttributeError):
            self.access_token = None
            self.refresh_token = None
            self.id_token = None

    def do_asserts(self):
        assert self.response.status_code == 200, self.response.json
        assert "access_token" in self.response.json
        assert "refresh_token" in self.response.json
        assert "id_token" in self.response.json


class OAuth2TestClient(object):
    """
    A client for testing which handles basic OAuth2 operations.

    *Things that ``OAuth2TestClient will test for (that don't need to be
    included elsewhere in the tests), as long as ``do_asserts=True``:*
    - Authorize endpoint:
        - The status code of the response (200 for POST, 302 for GET)
        - Resonse has redirect URL (in JSON for POST, headers for GET)
        - That the redirect URL is correct (same as URL of the client)
    - Token endpoint:
        - Status code is 200
        - The response contains all tokens (ID, access, refresh) in JSON
    - Revoke request:
        - Status code is 204

    Attributes:
        _auth_header (dict): basic auth header to include in all requests
        _client (werkzeug.test.Client): test client to send requests with
        authorize_response (AuthorizeResponse):
            response from the authorization endpoint
        client_id (str): OAuth client ID
        client_secret (str): OAuth client secret
        refresh_response (TokenResponse):
            response from the token endpoint for a refresh request
        token_response (TokenResponse): response from the token endpoint
        url (str): OAuth client redirect URL

    Example:

    .. code-block:: python

        @pytest.fixture(scope='function')
        def oauth_test_client(client, oauth_client):
            return OAuth2TestClient(client, oauth_client)

        def test_post_token(oauth_test_client):
            oauth_test_client.authorize(data={'confirm': 'yes'})
            code = oauth_test_client.authorize_response.code
            oauth_test_client.token()
            access_token = oauth_test_client.token_response.access_token
            refresh_token = oauth_test_client.token_response.refresh_token
            # etc.
    """

    PATH_AUTHORIZE = "/oauth2/authorize"
    PATH_TOKEN = "/oauth2/token"
    PATH_REFRESH = "/oauth2/token"
    PATH_REVOKE = "/oauth2/revoke"

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
            self._auth_header = tests.utils.oauth2.create_basic_header(
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
            str: authorize endpoint path including query string params
        """
        path = self.PATH_AUTHORIZE
        if params:
            path += "?" + urllib.parse.urlencode(query=params)
        return path

    def authorize(self, method="POST", data=None, do_asserts=True, include_auth=True):
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
            "client_id": self.client_id,
            "redirect_uri": self.url,
            "response_type": "code",
            "scope": "openid user",
            "state": fence.utils.random_str(10),
        }
        default_data.update(data)
        data = default_data
        if isinstance(data["scope"], list):
            data["scope"] = " ".join(data["scope"])

        headers = self._auth_header if include_auth else {}

        if method == "GET":
            response = self._client.get(
                path=self._path_for_authorize(params=data), headers=headers
            )
        elif method == "POST":
            response = self._client.post(
                path=self._path_for_authorize(), headers=headers, data=data
            )
        else:
            raise ValueError("cannot use method {}".format(method))

        self.authorize_response = AuthorizeResponse(response)

        if do_asserts:
            # Check the response code for success.
            # NOTE: GET should be returning a redirect (302), and POST should
            # be returning a 200 with the redirect in JSON.
            if method == "GET":
                if data.get("confirm") == "yes":
                    assert response.status_code == 302, response
                else:
                    assert response.status_code == 200, response
            elif method == "POST":
                assert response.status_code == 200, response
            # Check that the redirect does go to the correct URL.
            assert self.authorize_response.location.startswith(self.url)

        return self.authorize_response

    def token(self, code=None, data=None, do_asserts=True, include_auth=True):
        """
        Make a request to the token endpoint to get a set of tokens.

        Args:
            code (Optional[str]):
                code received from authorization endpoint; defaults to
                ``self.authorize_response.code``
            data (Optional[dict]): parameters to include in request
            do_asserts (bool): whether to call asserts on token response
        """
        if not code and not self.authorize_response:
            raise ValueError("no code provided")
        code = code or self.authorize_response.code
        data = data or {}
        default_data = {
            "client_id": self.client_id,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.url,
        }
        default_data.update(data)
        data = default_data
        if self.client_secret and include_auth:
            data["client_secret"] = self.client_secret
        headers = self._auth_header if include_auth else {}
        response = self._client.post(self.PATH_TOKEN, headers=headers, data=data)
        self.token_response = TokenResponse(response)
        if do_asserts:
            self.token_response.do_asserts()
        return self.token_response

    def refresh(self, refresh_token=None, do_asserts=True, data=None):
        """
        Make a request to the token endpoint to refresh and access token.

        Args:
            refresh_token (Optional[str]):
                refresh token to use; defaults to
                ``self.token_response.refresh_token``

            do_asserts (bool): whether to call asserts on token response
        """
        if not refresh_token and not self.token_response:
            raise ValueError("no refresh token provided")
        refresh_token = refresh_token or self.token_response.refresh_token
        data = data or {}
        default_data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        default_data.update(data)
        data = default_data
        if self.client_secret:
            data["client_secret"] = self.client_secret
        response = self._client.post(
            self.PATH_REFRESH, headers=self._auth_header, data=data
        )
        self.refresh_response = TokenResponse(response)
        if do_asserts:
            self.refresh_response.do_asserts()
        return self.refresh_response

    def revoke(self, refresh_token=None, do_asserts=True):
        """
        Make a request to the revoke endpoint to revoke an access token.

        Args:
            refresh_token (Optional[str]): refresh token to include in request
            do_asserts (bool): whether to call asserts on response
        """
        if not refresh_token and not self.token_response:
            raise ValueError("no refresh token provided")
        refresh_token = refresh_token or self.token_response.refresh_token
        response = self._client.post(
            self.PATH_REVOKE, headers=self._auth_header, data={"token": refresh_token}
        )
        if do_asserts:
            assert response.status_code == 200
