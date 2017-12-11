import os


def read_file(filename):
    """Read the contents of a file in the tests directory."""
    root_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(root_dir, filename), 'r') as f:
        return f.read()


def oauth_post_authorize(client, oauth_client, scope='user'):
    """
    Args:
        client: client fixture
        oauth_client: oauth client fixture
        scope: scope to request

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    path = (
        '/oauth2/authorize'
        '?client_id={client_id}'
        '&response_type=code'
        '&scope={scope}'
        '&redirect_uri={redirect_uri}'
    )
    path = path.format(
        client_id=oauth_client.client_id,
        scope=scope,
        redirect_uri=oauth_client.url,
    )
    return client.post(path, data={'confirm': 'yes'})


def code_from_authorize_response(response):
    """
    Get the code out from a response from ``/oauth2/authorize``.

    Args:
        response (pytest_flask.plugin.JSONResponse): response to get code from

    Return:
        str: the code
    """
    return response.headers['Location'].split('code=')[-1]


def oauth_post_token(client, oauth_client, code):
    """
    Return the response from ``POST /oauth2/token``.

    Args:
        client: client fixture
        oauth_client: oauth client fixture
        code (str): code obtained from oauth to exchange for token

    Return:
        pytest_flask.plugin.JSONResponse: the response
    """
    data = {
        'code': code,
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'redirect_uri': oauth_client.url,
        'grant_type': 'authorization_code',
    }
    return client.post('/oauth2/token', data=data)


def get_access_token(client, oauth_client):
    """
    Return an access token from going through the OAuth procedure.

    Args:
        client: client fixture
        oauth_client: oauth client fixture

    Return:
        str: an access token
    """
    code = code_from_authorize_response(oauth_post_authorize(
        client, oauth_client
    ))
    response = oauth_post_token(client, oauth_client, code)
    return response.json['access_token']
