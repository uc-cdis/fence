"""Store user passport

Revision ID: 5e264d6b3c16
Revises: bff33a927a37
Create Date: 2026-05-13 18:34:36.573153

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "5e264d6b3c16"
down_revision = "bff33a927a37"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_passport",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("passport", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
    )


def downgrade():
    op.drop_table("user_passport")
