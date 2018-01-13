import authlib.client

from fence import blueprints


class OAuth2Client(authlib.client.OAuthClient):

    def __init__(
            self, client_key=None, client_secret=None, access_token_url=None,
            access_token_params=None, refresh_token_url=None,
            refresh_token_params=None, authorize_url=None, api_base_url=None,
            client_kwargs=None, **kwargs):
        """
        Args:
            client_key (Optional[str]): the client ID
            client_secret (Optional[str]): the client secret
            access_token_url (Optional[str]):
                URL for the endpoint to get access token
            access_token_params (Optional[dict]):
                extra parameters to include for access token endpoint
            refresh_token_url (Optional[str]): URL
            refresh_token_params (Optional[dict]):
                extra parameters to include for refresh token endpoint
            authorize_url (str): URL for the authorization endpoint
            api_base_url (str): base URL for the client API
            client_kwargs (dict):
                extra arguments which get passed to the
                ``authlib.client.oauth2.OAuth2Session``.
        """
        super(OAuth2Client, self).__init__(
            client_key=client_key,
            client_secret=client_secret,
            access_token_url=access_token_url,
            access_token_params=access_token_params,
            refresh_token_url=refresh_token_url,
            refresh_token_params=refresh_token_params,
            authorize_url=authorize_url,
            api_base_url=api_base_url,
            client_kwargs=client_kwargs,
            **kwargs
        )
