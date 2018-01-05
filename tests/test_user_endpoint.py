"""
Test the endpoints in the ``/user`` blueprint.
"""


def test_user_protected(app, client, monkeypatch):
    """
    Test that the user endpoint cannot be accessed without some form of
    authorization.
    """
    monkeypatch.setitem(app.config, 'MOCK_AUTH', False)
    response = client.get('/user/')
    assert response.status_code == 401


def test_user_info(app, client, access_token, monkeypatch):
    """
    Test the return value of the root endpoint.
    """
    monkeypatch.setitem(app.config, 'MOCK_AUTH', False)
    headers = {'Authorization': 'bearer ' + access_token}
    response = client.get('/user/', headers=headers)
    required_info_list = [
        'user_id',
        'username',
        'resources_granted',
        'project_access',
        'certificates_uploaded',
        'email',
        'message',
    ]
    for required_info in required_info_list:
        assert required_info in response.json
