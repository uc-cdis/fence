import pytest


@pytest.fixture(scope='module')
def example_usernames():
    """Make a list of example usernames."""
    return ['A', 'B', 'C']


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
