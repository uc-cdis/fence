from fence.models import User
from fence.scripting.fence_create import (
    delete_users,
)


def test_delete_users(app, db_session, example_usernames, example_users):
    """
    Test the functionality of ``delete_users``.
    """
    for user in example_users:
        db_session.add(user)
        db_session.commit()
    # Delete all but the first user; check that the first one is still there
    # and the rest are gone.
    delete_users(app.config['DB'], example_usernames[1:])
    # Get the list of usernames for users that still exist.
    # (The `list(zip(...))` trick is to turn a list of 1-tuples into a
    # flattened list.)
    import pdb; pdb.set_trace()
    remaining_usernames = list(zip(*db_session.query(User.username).all())[0])
    assert example_usernames[0] in remaining_usernames
    for username in example_usernames[1:]:
        assert username not in remaining_usernames
