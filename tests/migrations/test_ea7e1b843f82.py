"""
"Optional Client.redirect_uri" migration
"""

from alembic.config import main as alembic_main
import pytest
from sqlalchemy.exc import IntegrityError

from fence.models import Client


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
    alembic_main(["--raiseerr", "downgrade", "e4c7b0ab68d3"])

    # before the migration, it should not be possible to create a client
    # without a redirect_uri
    with app.db.session as db_session:
        with pytest.raises(IntegrityError):
            db_session.add(
                Client(
                    client_id="client_without_redirect_uri",
                    name="client_without_redirect_uri_name",
                    grant_types="client_credentials",
                )
            )
            db_session.commit()
        db_session.rollback()

    # run the upgrade migration
    alembic_main(["--raiseerr", "upgrade", "ea7e1b843f82"])

    # now it should be possible
    with app.db.session as db_session:
        db_session.add(
            Client(
                client_id="client_without_redirect_uri",
                name="client_without_redirect_uri_name",
                grant_types="client_credentials",
            )
        )
        db_session.commit()
        query_result = db_session.query(Client).all()

    # make sure the client was created
    assert len(query_result) == 1, query_result
    assert query_result[0].client_id == "client_without_redirect_uri"
    assert query_result[0].redirect_uri == None


def test_downgrade(app):
    # state after migration
    alembic_main(["--raiseerr", "downgrade", "ea7e1b843f82"])

    with app.db.session as db_session:
        # it should possible to create a client without a redirect_uri
        db_session.add(
            Client(
                client_id="client_without_redirect_uri",
                name="client_without_redirect_uri_name",
                grant_types="client_credentials",
            )
        )
        # also create a client with a redirect_uri
        db_session.add(
            Client(
                client_id="client_with_redirect_uri",
                name="client_with_redirect_uri_name",
                grant_types="client_credentials",
                redirect_uri="http://localhost/redirect",
            )
        )
        query_result = db_session.query(Client).all()

    # make sure the clients were created
    assert len(query_result) == 2, query_result

    client_without_redirect_uri = [
        c for c in query_result if c.client_id == "client_without_redirect_uri"
    ]
    assert len(client_without_redirect_uri) == 1
    assert client_without_redirect_uri[0].redirect_uri == None

    client_with_redirect_uri = [
        c for c in query_result if c.client_id == "client_with_redirect_uri"
    ]
    assert len(client_with_redirect_uri) == 1
    assert client_with_redirect_uri[0].redirect_uri == "http://localhost/redirect"

    # run the downgrade migration
    alembic_main(["--raiseerr", "downgrade", "e4c7b0ab68d3"])

    with app.db.session as db_session:
        query_result = db_session.query(Client).all()
    assert len(query_result) == 2, query_result

    # make sure the client without redirect was migrated to have an empty
    # string as redirect_uri instead of null
    client_without_redirect_uri = [
        c for c in query_result if c.client_id == "client_without_redirect_uri"
    ]
    assert len(client_without_redirect_uri) == 1
    assert client_without_redirect_uri[0].redirect_uri == ""

    # make sure the client with redirect is unchanged
    client_with_redirect_uri = [
        c for c in query_result if c.client_id == "client_with_redirect_uri"
    ]
    assert len(client_with_redirect_uri) == 1
    assert client_with_redirect_uri[0].redirect_uri == "http://localhost/redirect"
