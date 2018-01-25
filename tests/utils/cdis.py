import json


def get_refresh_token(client):
    """
    Args:
        client: client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    path = (
        '/credentials/cdis/'
    )
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = client.post(path, data={'scopes': ['data', 'user']}, headers=headers)
    return response


def get_refresh_token_with_json(client):
    """
    Args:
        client: client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    path = (
        '/credentials/cdis/'
    )
    headers = {
        'Content-Type': 'application/json'
    }
    response = client.post(path, data=json.dumps({'scopes': ['data', 'user']}), headers=headers)
    return response
