"""Remove foreign key constraint for google_service_account

Revision ID: e695e299f6a6
Revises: 9b3a5a7145d7
Create Date: 2024-08-07 14:39:11.844356

"""
from alembic import op
import logging
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "e695e299f6a6"
down_revision = "9b3a5a7145d7"  # pragma: allowlist secret
branch_labels = None
depends_on = None

logger = logging.getLogger("fence.alembic")


def upgrade():
    """
    Pre-alembic era created a foreign key clent_id(from the client table) on the google_service_account table.
    This foreign key was then removed from the schema but any commons created before the constraint was removed
    still held the foreign key.
    The previous alembic migration tuncates the client table but this fails if the foreign key constraint still persists
    therefore failing the migration.
    This migration checks for the existence of the foreign key constraint and removes it if it exists.
    There is no downgrade path for this since not having the foreign key constraint is the correct schema throughout all versions.
    This migration is specifically for commons that were created before the foreign key constraint was removed
    """
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    foreign_keys = inspector.get_foreign_keys("google_service_account")
    fk_exists = False

    for fk in foreign_keys:
        if "client_id" in fk["constrained_columns"]:
            fk_exists = True

    if fk_exists:
        logger.info("Foreign key client_id exists. Removing constraint...")
        op.drop_constraint(
            "client_id",
            "google_service_account",
            type_="foreignkey",
        )
    else:
        logger.info("Foreign key client_id does not exist.")


def downgrade():
    """
    There is no downgrade path for this since not having the foreign key constraint is the correct schema throughout all versions.
    """
    pass
