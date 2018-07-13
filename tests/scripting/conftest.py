import pytest
from collections import OrderedDict
from mock import MagicMock
import cirrus
@pytest.fixture(scope='module')
def example_usernames():
    """Make a list of example usernames."""
    return ['A', 'B', 'C']

def get_test_cloud_manager():
    project_id = "test_project"
    manager = cirrus.GoogleCloudManager(project_id)
    manager._authed_session = MagicMock()
    manager._admin_service = MagicMock()
    manager._storage_client = MagicMock()
    manager.credentials = MagicMock()
    return manager


@pytest.fixture
def test_cloud_manager():
    patcher = patch('cirrus.google_cloud.manager.ServiceAccountCredentials.from_service_account_file')
    patcher.start()
    yield get_test_cloud_manager()
    patcher.stop()

@pytest.fixture(scope='function', autouse=True)
def patch_driver(db, monkeypatch):
    """
    Change the database driver in ``fence.scripting.fence_create`` to use the
    one from the test fixtures.
    """
    monkeypatch.setattr(
        'fence.scripting.fence_create.SQLAlchemyDriver',
        lambda _: db,
    )
