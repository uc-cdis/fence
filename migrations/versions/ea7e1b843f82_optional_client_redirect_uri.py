"""Optional Client.redirect_uri

Revision ID: ea7e1b843f82
Revises: e4c7b0ab68d3
Create Date: 2022-07-27 16:49:52.793557

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "ea7e1b843f82"
down_revision = "e4c7b0ab68d3"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("client", "redirect_uri", nullable=True)


def downgrade():
    # replace null values with an empty string
    op.execute(sa.text("UPDATE client SET redirect_uri='' WHERE redirect_uri IS NULL"))
    op.alter_column("client", "redirect_uri", nullable=False)
