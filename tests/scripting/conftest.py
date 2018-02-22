import pytest

from fence.models import User


@pytest.fixture(scope='session')
def example_usernames():
    return ['A', 'B', 'C']


@pytest.fixture(scope='session')
def example_users(example_usernames):
    return [User(username=username) for username in example_usernames]
