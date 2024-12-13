"""Make User.active field non nullable

Revision ID: 3a5712474808
Revises: 9b3a5a7145d7
Create Date: 2024-11-08 22:00:41.161934

"""
from alembic import op
import sqlalchemy as sa
from userdatamodel.models import User
from sqlalchemy.orm import Session


# revision identifiers, used by Alembic.
revision = "3a5712474808"  # pragma: allowlist secret
down_revision = "9b3a5a7145d7"  # pragma: allowlist secret
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    session = Session(bind=conn)
    session.query(User)
    active_users_count = session.query(User).filter(User.active.is_(True)).count()
    if active_users_count > 0:
        # if we have at least one user where "active" is explicitly set to "True", then we'll assume NULL is to mean "False":
        op.execute('UPDATE "User" SET active = False WHERE active IS NULL')
    else:
        # else, we assume NULL means "True"
        op.execute('UPDATE "User" SET active = True WHERE active IS NULL')
    op.alter_column("User", "active", nullable=False, server_default="True")


def downgrade():
    op.alter_column("User", "active", nullable=True, server_default=None)
