"""
"Remove foreign key constraint for google_service_account" migration
"""

from alembic.config import main as alembic_main
import pytest
from sqlalchemy import inspect

from fence.models import Client


@pytest.fixture(scope="function", autouse=True)
def post_test_clean_up(app):
    yield

    # clean up the client table
    with app.db.session as db_session:
        db_session.query(Client).delete()

    # go back to the latest state of the DB
    # alembic_main(["--raiseerr", "upgrade", "head"])


def test_upgrade_with_fk_constraint(app):
    """
    Add foreign key constraint client_id for google_service_account and make sure it gets removed after migration
    """
    # Make sure we start with a previous version of alembic
    alembic_main(
        ["--raiseerr", "downgrade", "9b3a5a7145d7"]  # pragma: allowlist secret
    )

    with app.db.session as db_session:
        inspector = inspect(app.db.engine)
        foreign_keys = inspector.get_foreign_keys("google_service_account")
        constraint_exists = any(
            fk["constrained_columns"] == ["client_id"] for fk in foreign_keys
        )

        if constraint_exists:
            db_session.execute(
                f"ALTER TABLE google_service_account DROP CONSTRAINT client_id;"
            )
            db_session.commit()

        db_session.execute(
            """
        ALTER TABLE google_service_account
        ADD CONSTRAINT client_id FOREIGN KEY (client_id) REFERENCES client(client_id);
        """
        )
        db_session.commit()

    alembic_main(["--raiseerr", "upgrade", "e695e299f6a6"])  # pragma: allowlist secret

    with app.db.session as db_session:
        inspector = inspect(app.db.engine)
        foreign_keys = inspector.get_foreign_keys("google_service_account")
        constraint_exists = any(
            fk["constrained_columns"] == ["client_id"] for fk in foreign_keys
        )
        assert constraint_exists == False


def test_upgrade_without_fk_constraint(app):
    """
    If foreign key constraint does not exists, make sure no changes are made to google_service_account table
    """
    # Make sure we start with a previous version of alembic
    alembic_main(
        ["--raiseerr", "downgrade", "9b3a5a7145d7"]  # pragma: allowlist secret
    )

    with app.db.session as db_session:
        inspector = inspect(app.db.engine)
        foreign_keys = inspector.get_foreign_keys("google_service_account")
        constraint_exists = any(
            fk["constrained_columns"] == ["client_id"] for fk in foreign_keys
        )

        if constraint_exists:
            db_session.execute(
                f"ALTER TABLE google_service_account DROP CONSTRAINT client_id;"
            )
            db_session.commit()

    alembic_main(["--raiseerr", "upgrade", "e695e299f6a6"])  # pragma: allowlist secret

    with app.db.session as db_session:
        inspector = inspect(app.db.engine)
        foreign_keys = inspector.get_foreign_keys("google_service_account")
        constraint_exists = any(
            fk["constrained_columns"] == ["client_id"] for fk in foreign_keys
        )
        assert constraint_exists == False
