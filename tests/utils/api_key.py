import json


DEFAULT_SCOPE = ["fence", "data", "user"]


def get_api_key(client, encoded_credentials_jwt, scope=None, expires_in=None):
    """
    Args:
        client: client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    path = f"/credentials/api/{f'?expires_in={expires_in}' if expires_in else ''}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer " + str(encoded_credentials_jwt),
    }
    scope = scope or DEFAULT_SCOPE
    response = client.post(path, data={"scope": scope}, headers=headers)
    return response


def get_api_key_with_json(client, encoded_credentials_jwt, scope=None):
    """
    Args:
        client: client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    scope = scope or DEFAULT_SCOPE
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + str(encoded_credentials_jwt),
    }
    response = client.post(
        "/credentials/api/", headers=headers, data=json.dumps({"scope": scope})
    )
    return response
