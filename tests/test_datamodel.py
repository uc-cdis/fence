from fence.models import User, Client
from fence.utils import random_str


def test_user_delete_cascade(db_session):
    """
    test deleting a user will cascade to its children
    """
    user = User(username='test_user')
    client = Client(
        name='test_client', user=user,
        client_id=random_str(40), client_secret=random_str(60))
    db_session.add(user)
    db_session.add(client)
    db_session.flush()
    assert len(user.clients) == 1
    db_session.delete(user)
    assert (
        db_session.query(Client).filter_by(client_id=client.client_id).count()
        == 0
    )
