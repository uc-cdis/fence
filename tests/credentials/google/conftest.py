import pytest


@pytest.fixture(scope='function', autouse=True)
def mock_auth(set_mock_auth):
    set_mock_auth()
