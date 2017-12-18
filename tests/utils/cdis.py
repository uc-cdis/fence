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
    response = client.post(path)
    return response
