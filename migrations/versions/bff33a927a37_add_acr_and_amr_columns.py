"""add acr and amr columns

Revision ID: bff33a927a37
Revises: 3a5712474808
Create Date: 2025-10-21 15:44:42.028779

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "bff33a927a37"
down_revision = "3a5712474808"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("authorization_code", sa.Column("acr", sa.Text(), nullable=True))
    op.add_column("authorization_code", sa.Column("amr", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("authorization_code", "acr")
    op.drop_column("authorization_code", "amr")
