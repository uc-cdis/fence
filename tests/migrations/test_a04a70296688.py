"""
"Non-unique client name" migration
"""

from alembic.config import main as alembic_main
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from fence.models import Client
from fence.utils import random_str


@pytest.fixture(scope="function", autouse=True)
def post_test_clean_up(app):
    yield

    # Rebuild from an empty schema rather than migrating back up. Postgres never
    # reclaims the attnum (pg_attribute for the number of the columns up from 1) of a dropped column,
    # so migrating this table down and up
    # repeatedly walks it into the hard 1600-column ceiling on a database that
    # outlives a single run (e.g. if you set up a test database and use it for years,
    # you'll randomly hit a strange failure and not understand why.....)
    with app.db.engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))

    alembic_main(["--raiseerr", "upgrade", "head"])


def test_upgrade(app):
    # This is the last version our current codebase will work with
    alembic_main(["--raiseerr", "upgrade", "9b3a5a7145d7"])  # pragma: allowlist secret

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
