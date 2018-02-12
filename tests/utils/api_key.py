import json


DEFAULT_SCOPE = ['fence', 'data', 'user']


def get_api_key(client, scope=None):
    """
    Args:
        client: client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    path = '/credentials/cdis/'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    scope = scope or DEFAULT_SCOPE
    response = client.post(path, data={'scope': scope}, headers=headers)
    return response


def get_api_key_with_json(client, scope=None):
    """
    Args:
        client: client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    scope = scope or DEFAULT_SCOPE
    headers = {
        'Content-Type': 'application/json'
    }
    response = client.post(
        '/credentials/cdis/',
        headers=headers,
        data=json.dumps({'scope': scope}),
    )
    return response
