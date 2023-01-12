"""Non-unique client name

Revision ID: a04a70296688
Revises: ea7e1b843f82
Create Date: 2022-12-23 09:36:28.425744

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "a04a70296688"
down_revision = "ea7e1b843f82"
branch_labels = None
depends_on = None


def upgrade():
    # the `name` does not have to be unique anymore
    op.drop_constraint("client_name_key", "client")


def downgrade():
    # remove duplicate rows (rows with the same `name`):
    # for each client `name`, only keep the row with the latest expiration
    op.execute(
        """DELETE FROM client WHERE client_id IN (
            SELECT client_id FROM (
                SELECT client_id, ROW_NUMBER() OVER(PARTITION BY name ORDER BY expires_at DESC)
                AS row_num FROM client
            ) dup where dup.row_num > 1
        )"""
    )

    # the `name` must be unique
    op.create_unique_constraint("client_name_key", "client", ["name"])
