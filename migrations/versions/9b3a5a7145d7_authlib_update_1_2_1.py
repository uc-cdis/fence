"""authlib update 1.2.1

Revision ID: 9b3a5a7145d7
Revises: a04a70296688
Create Date: 2023-09-01 10:27:16.686456

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import Column, String

# revision identifiers, used by Alembic.
revision = "9b3a5a7145d7"  # pragma: allowlist secret
down_revision = "a04a70296688"  # pragma: allowlist secret
branch_labels = None
depends_on = None


def upgrade():
    # Add New Columns for client Table
    op.add_column("client", sa.Column("client_metadata", sa.Text(), nullable=True))
    op.add_column(
        "client", sa.Column("client_secret_expires_at", sa.Integer(), nullable=False)
    )

    # Modify Columns for client Table
    op.alter_column("client", "issued_at", new_column_name="client_id_issued_at")
    op.alter_column("client", "client_id", nullable=False, type_=sa.String(48))
    op.alter_column("client", "client_secret", nullable=True, type_=sa.String(120))

    # Delete Columns for client Table
    op.drop_column("client", "redirect_uri")
    op.drop_column("client", "token_endpoint_auth_method")
    op.drop_column("client", "grant_type")
    op.drop_column("client", "response_type")
    op.drop_column("client", "scope")
    op.drop_column("client", "client_name")
    op.drop_column("client", "client_uri")
    op.drop_column("client", "logo_uri")
    op.drop_column("client", "contact")
    op.drop_column("client", "tos_uri")
    op.drop_column("client", "policy_uri")
    op.drop_column("client", "jwks_uri")
    op.drop_column("client", "jwks_text")
    op.drop_column("client", "i18n_metadata")
    op.drop_column("client", "software_id")
    op.drop_column("client", "software_version")
    op.drop_column("client", "_allowed_scopes")
    op.drop_column("client", "_redirect_uris")

    # Add New Columns for authorization_code Table
    op.add_column(
        "authorization_code", sa.Column("code_challenge", sa.Text(), nullable=True)
    )
    op.add_column(
        "authorization_code",
        sa.Column("code_challenge_method", sa.String(length=48), nullable=True),
    )


def downgrade():

    # Add New Columns for client Table
    op.drop_column("client", "client_metadata")
    op.drop_column("client", "client_secret_expires_at")

    # Modify Columns for client Table
    op.alter_column("client", "client_id_issued_at", new_column_name="issued_at")
    op.alter_column("client", "client_id", nullable=False, type_=sa.String(40))
    op.alter_column("client", "client_secret", nullable=True, type_=sa.String(60))

    # Add Old Columns Back
    op.add_column("client", sa.Column("redirect_uri", sa.Text(), nullable=True))
    op.add_column(
        "client",
        sa.Column("token_endpoint_auth_method", sa.String(length=48), nullable=True),
    )
    op.add_column("client", sa.Column("grant_type", sa.Text(), nullable=False))
    op.add_column("client", sa.Column("response_type", sa.Text(), nullable=False))
    op.add_column("client", sa.Column("scope", sa.Text(), nullable=False))
    op.add_column(
        "client", sa.Column("client_name", sa.String(length=100), nullable=True)
    )
    op.add_column("client", sa.Column("client_uri", sa.Text(), nullable=True))
    op.add_column("client", sa.Column("logo_uri", sa.Text(), nullable=True))
    op.add_column("client", sa.Column("contact", sa.Text(), nullable=True))
    op.add_column("client", sa.Column("tos_uri", sa.Text(), nullable=True))
    op.add_column("client", sa.Column("policy_uri", sa.Text(), nullable=True))
    op.add_column("client", sa.Column("jwks_uri", sa.Text(), nullable=True))
    op.add_column("client", sa.Column("jwks_text", sa.Text(), nullable=True))
    op.add_column("client", sa.Column("i18n_metadata", sa.Text(), nullable=True))
    op.add_column(
        "client", sa.Column("software_id", sa.String(length=36), nullable=True)
    )
    op.add_column(
        "client", sa.Column("software_version", sa.String(length=48), nullable=True)
    )
    op.add_column("client", sa.Column("_allowed_scopes", sa.Text(), nullable=False))
    op.add_column("client", sa.Column("_redirect_uris", sa.Text(), nullable=True))

    # Remove New Columns for authorization_code Table
    op.drop_column("authorization_code", "code_challenge")
    op.drop_column("authorization_code", "code_challenge_method")
