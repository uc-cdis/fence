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
    # state before migration
    alembic_main(["--raiseerr", "downgrade", "ea7e1b843f82"])

    client_name = "non_unique_client_name"

    # before the migration, it should not be possible to create 2 clients
    # with the same name
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
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

    # run the upgrade migration
    alembic_main(["--raiseerr", "upgrade", "a04a70296688"])

    # now it should be possible
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


@pytest.mark.parametrize("expirations", [[1, 100], [0, 0], [0, 100]])
def test_downgrade(app, expirations):
    """
    Test the downgrade with the following expiration values:
    - 1 and 100: we keep the row with the highest expiration (100)
    - 0 and 0: both rows have no expiration: we keep any of the 2
    - 0 and 100: we keep the row that has an expiration (100)
    """
    # state after migration
    alembic_main(["--raiseerr", "downgrade", "a04a70296688"])

    client_name = "non_unique_client_name"

    # it should be possible to create 2 clients with the same name
    with app.db.session as db_session:
        db_session.add(
            Client(
                name=client_name,
                client_id="client_id1",
                grant_types="client_credentials",
                expires_in=expirations[0],
            )
        )
        db_session.add(
            Client(
                name=client_name,
                client_id="client_id2",
                grant_types="client_credentials",
                expires_in=expirations[1],
            )
        )
        db_session.commit()
        query_result = db_session.query(Client).all()

    assert len(query_result) == 2, query_result
    assert query_result[0].name == client_name
    expires_at1 = query_result[0].expires_at
    assert query_result[1].name == client_name
    expires_at2 = query_result[1].expires_at

    # run the downgrade migration
    alembic_main(["--raiseerr", "downgrade", "ea7e1b843f82"])

    # the duplicate row with the lowest expiration should have been deleted
    with app.db.session as db_session:
        query_result = db_session.query(Client).all()
    assert len(query_result) == 1, query_result
    assert query_result[0].name == client_name
    assert query_result[0].expires_at == max(expires_at1, expires_at2)

    # now it should not be possible anymore to create 2 clients with the same name
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
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
