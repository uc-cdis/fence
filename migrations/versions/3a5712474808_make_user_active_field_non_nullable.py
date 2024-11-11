"""Make User.active field non nullable

Revision ID: 3a5712474808
Revises: 9b3a5a7145d7
Create Date: 2024-11-08 22:00:41.161934

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "3a5712474808"  # pragma: allowlist secret
down_revision = "9b3a5a7145d7"  # pragma: allowlist secret
branch_labels = None
depends_on = None


def upgrade():
    op.execute('UPDATE "User" SET active = True WHERE active IS NULL')
    op.alter_column("User", "active", nullable=False, server_default="True")


def downgrade():
    op.alter_column("User", "active", nullable=True, server_default=None)
    op.execute('UPDATE "User" SET active = NULL WHERE active = True')
