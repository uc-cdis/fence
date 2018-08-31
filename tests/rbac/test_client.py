"""
Run some basic tests that the methods on ``ArboristClient`` actually try to hit
the correct URLs on the arborist API.
"""

# Python 2 and 3 compatible
try:
    from unittest import mock
except ImportError:
    import mock


from fence.rbac.client import ArboristClient


def test_healthy_call(arborist_client):
    with mock.patch('fence.rbac.client.requests.get') as mock_get:
        arborist_client.healthy()
        assert mock_get.called_with(arborist_client._base_url + '/health')


def test_get_resource_call(arborist_client):
    with mock.patch('fence.rbac.client.requests.get') as mock_get:
        arborist_client.get_resource('/a/b/c')
        assert mock_get.called_with(
            arborist_client._base_url + '/resource/a/b/c'
        )


def test_list_policies_call(arborist_client):
    with mock.patch('fence.rbac.client.requests.get') as mock_get:
        arborist_client.list_policies()
        assert mock_get.called_with(arborist_client._base_url + '/policy/')


def test_policies_not_exist_call(arborist_client):
    with mock.patch('fence.rbac.client.requests.get') as mock_get:
        arborist_client.policies_not_exist(['foo-bar'])
        assert mock_get.called_with(arborist_client._base_url + '/policy/')


def test_create_resource_call(arborist_client):
    with mock.patch('fence.rbac.client.requests.post') as mock_post:
        arborist_client.create_resource('/', {'name': 'test'})
        assert mock_post.called_with(arborist_client._base_url + '/resource/')


def test_create_role_call(arborist_client):
    with mock.patch('fence.rbac.client.requests.post') as mock_post:
        arborist_client.create_role({'id': 'test'})
        assert mock_post.called_with(arborist_client._base_url + '/role/')


def test_create_policy(arborist_client):
    with mock.patch('fence.rbac.client.requests.post') as mock_post:
        arborist_client.create_role({
            'id': 'test',
            'resource_paths': ['/'],
            'role_ids': ['test'],
        })
        assert mock_post.called_with(arborist_client._base_url + '/policy/')
