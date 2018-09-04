import json


DEFAULT_SCOPE = ["fence", "data", "user"]


def get_api_key(client, encoded_credentials_jwt, scope=None):
    """
    Args:
        client: client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    path = "/credentials/cdis/"
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
        "/credentials/cdis/", headers=headers, data=json.dumps({"scope": scope})
    )
    return response
