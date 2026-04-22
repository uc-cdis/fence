"""Non-unique client name

Revision ID: a04a70296688
Revises: ea7e1b843f82
Create Date: 2022-12-23 09:36:28.425744

"""

from alembic import op
from sqlalchemy import text
import logging


# revision identifiers, used by Alembic.
revision = "a04a70296688"
down_revision = "ea7e1b843f82"
branch_labels = None
depends_on = None

logger = logging.getLogger("fence.alembic")


def upgrade():
    # get all "unique" constraints on "client" table
    connection = op.get_bind()
    results = connection.execute(
        text(
            "SELECT conname FROM pg_constraint WHERE conrelid = 'client'::regclass and contype = 'u'"
        )
    )

    # filter out the constraints that are not for the "name" column
    name_constraints = [e[0] for e in results if "name" in e[0]]
    logger.info(
        f"Found {len(name_constraints)} 'unique client name' constraints; deleting all of them: {name_constraints}"
    )

    # the `name` does not have to be unique anymore: remove the constraints
    for name in name_constraints:
        logger.info(f"Droppping 'unique client name' constraint: '{name}'")
        op.drop_constraint(name, "client")


def downgrade():
    # remove duplicate rows (rows with the same `name`):
    # for each client `name`, only keep the row with the latest expiration
    op.execute(
        text(
            """DELETE FROM client WHERE client_id IN (
            SELECT client_id FROM (
                SELECT client_id, ROW_NUMBER() OVER(PARTITION BY name ORDER BY expires_at DESC)
                AS row_num FROM client
            ) dup where dup.row_num > 1
        )"""
        )
    )

    # the `name` must be unique
    op.create_unique_constraint("unique_client_name", "client", ["name"])
