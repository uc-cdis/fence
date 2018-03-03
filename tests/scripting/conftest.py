import pytest

from fence.models import User


@pytest.fixture(scope='module')
def example_usernames():
    return ['A', 'B', 'C']


@pytest.fixture(scope='module')
def example_users(example_usernames):
    return [User(username=username) for username in example_usernames]


@pytest.fixture(scope='function', autouse=True)
def patch_driver(db, monkeypatch):
    monkeypatch.setattr(
        'fence.scripting.fence_create.SQLAlchemyDriver',
        lambda _: db,
    )
