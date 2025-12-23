"""
"Non-unique client name" migration
"""

from alembic.config import main as alembic_main
import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy import inspect, text

from fence.models import Client
from fence.utils import random_str
import bcrypt


@pytest.fixture(scope="function", autouse=True)
def post_test_clean_up(app):
    yield

    # clean up the client table
    with app.db.session as db_session:
        db_session.query(Client).delete()

    # go back to the latest state of the DB
    alembic_main(["--raiseerr", "upgrade", "head"])


def test_upgrade(app):
    """
    Test Adding Client after performing Alembic Upgrade to this revision
    Add foreign key constraint client_id for google_service_account and make sure it gets removed after migration
    """

    alembic_main(
        ["--raiseerr", "downgrade", "a04a70296688"]
    )  # pragma: allowlist secret

    with app.db.session as db_session:
        inspector = inspect(app.db.engine)
        foreign_keys = inspector.get_foreign_keys("google_service_account")
        constraint_exists = any(
            fk["constrained_columns"] == ["client_id"] for fk in foreign_keys
        )
        if constraint_exists:
            db_session.execute(
                text(
                    """
                ALTER TABLE google_service_account
                DROP CONSTRAINT google_service_account_client_id_fkey
                """
                )
            )
            db_session.commit()

        db_session.execute(
            text(
                """
            ALTER TABLE google_service_account
            ADD CONSTRAINT google_service_account_client_id_fkey
            FOREIGN KEY (client_id)
            REFERENCES client(client_id)
            """
            )
        )
        db_session.commit()

    alembic_main(["--raiseerr", "upgrade", "9b3a5a7145d7"])  # pragma: allowlist secret

    with app.db.session as db_session:
        inspector = inspect(app.db.engine)
        foreign_keys = inspector.get_foreign_keys("google_service_account")
        constraint_exists = any(
            fk["constrained_columns"] == ["client_id"] for fk in foreign_keys
        )
        assert constraint_exists == False

    client_name = "client_name"
    url = "https://oauth-client.net"
    client_id = "test-client"
    client_secret = random_str(50)
    hashed_secret = bcrypt.hashpw(
        client_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    grant_types = ["refresh_token"]
    allowed_scopes = ["openid", "user", "fence"]
    with app.db.session as db_session:
        db_session.add(
            Client(
                client_id=client_id,
                client_secret=hashed_secret,
                allowed_scopes=allowed_scopes,
                redirect_uris=[url],
                description="",
                is_confidential=True,
                name=client_name,
                grant_types=grant_types,
            )
        )
        db_session.commit()
        query_result = db_session.query(Client).all()

    # make sure the client was created and the new _client_metadata field is populated and Authlib getters are working
    assert len(query_result) == 1, query_result
    assert query_result[0].name == client_name
    assert query_result[0].client_secret == hashed_secret
    assert query_result[0].scope == " ".join(allowed_scopes)
    assert query_result[0].grant_types == grant_types
    assert query_result[0].redirect_uris == [url]


def test_upgrade_without_fk_constraint(app):
    """
    If foreign key constraint does not exists, make sure no changes are made to google_service_account table
    """
    # Make sure we start with a previous version of alembic
    alembic_main(
        ["--raiseerr", "downgrade", "a04a70296688"]  # pragma: allowlist secret
    )

    with app.db.session as db_session:
        inspector = inspect(app.db.engine)
        foreign_keys = inspector.get_foreign_keys("google_service_account")
        constraint_exists = any(
            fk["constrained_columns"] == ["client_id"] for fk in foreign_keys
        )

        if constraint_exists:
            db_session.execute(
                text(
                    """
                ALTER TABLE google_service_account
                DROP CONSTRAINT google_service_account_client_id_fkey
                """
                )
            )
            db_session.commit()

    alembic_main(["--raiseerr", "upgrade", "9b3a5a7145d7"])  # pragma: allowlist secret

    with app.db.session as db_session:
        inspector = inspect(app.db.engine)
        foreign_keys = inspector.get_foreign_keys("google_service_account")
        constraint_exists = any(
            fk["constrained_columns"] == ["client_id"] for fk in foreign_keys
        )
        assert constraint_exists == False
