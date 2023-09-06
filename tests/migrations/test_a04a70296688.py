"""
"Non-unique client name" migration
"""

from alembic.config import main as alembic_main
import pytest
from sqlalchemy.exc import IntegrityError

from fence.models import Client
from fence.utils import random_str


@pytest.fixture(scope="function", autouse=True)
def post_test_clean_up(app):
    yield

    # clean up the client table
    with app.db.session as db_session:
        db_session.query(Client).delete()

    # go back to the latest state of the DB
    alembic_main(["--raiseerr", "upgrade", "head"])


def test_upgrade(app):
    client_name = "non_unique_client_name"

    # It should be possible to add 2 clients of the same name
    with app.db.session as db_session:
        db_session.add(
            Client(
                name=client_name,
                client_id="client_id1",
                grant_types="client_credentials",
            )
        )
        db_session.add(
            Client(
                name=client_name,
                client_id="client_id2",
                grant_types="client_credentials",
            )
        )
        db_session.commit()
        query_result = db_session.query(Client).all()

    # make sure the client was created
    assert len(query_result) == 2, query_result
    assert query_result[0].name == client_name
    assert query_result[1].name == client_name
