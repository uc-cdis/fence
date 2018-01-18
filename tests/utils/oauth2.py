import fence.utils


def make_query_string(params):
    if not params:
        return ''
    params_str = '&'.join(
        '{}={}'.format(key, value)
        for key, value in params.iteritems()
    )
    return '?' + params_str


def path_for_authorize(params=None):
    return '/oauth2/authorize' + make_query_string(params)


def post_authorize(client, oauth_client, data=None):
    """
    Args:
        client: client fixture
        oauth_client: oauth client fixture
        scope: scope to request

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    data = data or {}
    default_data = {
        'client_id': oauth_client.client_id,
        'redirect_uri': oauth_client.url,
        'response_type': 'code',
        'scope': 'openid',
        'state': fence.utils.random_str(10),
        'confirm': 'yes',
    }
    default_data.update(data)
    data = default_data
    return client.post(path_for_authorize(), data=data)


def code_from_authorize_response(response):
    """
    Get the code out from a response from ``/oauth2/authorize``.

    Args:
        response (pytest_flask.plugin.JSONResponse): response to get code from

    Return:
        str: the code
    """
    return response.headers['Location'].split('code=')[-1]


def get_access_code(client, oauth_client, scope='openid'):
    """
    Do all steps to get an authorization code from ``/oauth2/authorize``

    Args:
        client: client fixture
        oauth_client: oauth client fixture
        scope: scope to request

    Return:
        str: the authorization code
    """
    data = {
        'confirm': 'yes',
        'scope': scope,
    }
    return code_from_authorize_response(post_authorize(
        client, oauth_client, data=data
    ))


def post_token(client, oauth_client, code):
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
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': oauth_client.url,
    }
    return client.post('/oauth2/token', data=data)


def get_token_response(client, oauth_client):
    """
    Args:
        client: client fixture
        oauth_client: oauth client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from ``/oauth2/token``
    """
    code = get_access_code(client, oauth_client)
    return post_token(client, oauth_client, code)
