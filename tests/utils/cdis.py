def get_refresh_token(client):
    """
    Args:
        client: client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    data = {'scope': 'fence'}
    response = client.post('/credentials/cdis/', data=data)
    return response
