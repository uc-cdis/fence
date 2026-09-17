"""add dpop_proof_jti

Revision ID: d7c1f0a9b2e4
Revises: bff33a927a37
Create Date: 2026-08-21 11:45:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "d7c1f0a9b2e4"  # pragma: allowlist secret
down_revision = "bff33a927a37"  # pragma: allowlist secret
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dpop_proof_jti",
        sa.Column("jti", sa.Text(), nullable=False),
        sa.Column("exp", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("jti"),
    )


def downgrade():
    op.drop_table("dpop_proof_jti")
