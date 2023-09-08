"""authlib update 1.2.1

Revision ID: 9b3a5a7145d7
Revises: a04a70296688
Create Date: 2023-09-01 10:27:16.686456

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session

import json
from authlib.common.encoding import json_loads, json_dumps

from migrations.models.migration_client import MigrationClient


# revision identifiers, used by Alembic.
revision = "9b3a5a7145d7"  # pragma: allowlist secret
down_revision = "a04a70296688"  # pragma: allowlist secret
branch_labels = None
depends_on = None


def upgrade():
    # Add New Columns for client Table
    op.add_column("client", sa.Column("client_metadata", sa.Text(), nullable=True))
    op.add_column(
        "client",
        sa.Column(
            "client_secret_expires_at", sa.Integer(), nullable=False, server_default="0"
        ),
    )

    # Modify Columns for client Table
    op.alter_column("client", "issued_at", new_column_name="client_id_issued_at")
    op.alter_column("client", "client_id", nullable=False, type_=sa.String(48))
    op.alter_column("client", "client_secret", nullable=True, type_=sa.String(120))

    # Set value of metadata field
    # Important: do this before deleting old columns to avoid issues
    # Also do this after adding columns
    set_metadata_values(op)

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

    # Add Old Columns Back
    op.add_column("client", sa.Column("redirect_uri", sa.Text(), nullable=True))
    op.add_column(
        "client",
        sa.Column("token_endpoint_auth_method", sa.String(length=48), nullable=True),
    )
    op.add_column(
        "client", sa.Column("grant_type", sa.Text(), nullable=False, server_default="")
    )
    op.add_column(
        "client",
        sa.Column("response_type", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "client", sa.Column("scope", sa.Text(), nullable=False, server_default="")
    )
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
    op.add_column(
        "client",
        sa.Column("_allowed_scopes", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column("client", sa.Column("_redirect_uris", sa.Text(), nullable=True))

    # Set value of old columns
    # Important: do this before deleting old columns to avoid issues
    # Also do this after adding columns
    set_old_column_values()

    # Modify Columns for client Table
    op.alter_column("client", "client_id_issued_at", new_column_name="issued_at")
    op.alter_column("client", "client_id", nullable=False, type_=sa.String(40))
    op.alter_column("client", "client_secret", nullable=True, type_=sa.String(60))

    # Drop New Columns for client Table
    op.drop_column("client", "client_metadata")
    op.drop_column("client", "client_secret_expires_at")

    # Remove New Columns for authorization_code Table
    op.drop_column("authorization_code", "code_challenge")
    op.drop_column("authorization_code", "code_challenge_method")


def set_metadata_values(op):
    conn = op.get_bind()
    session = Session(bind=conn)
    # Drop temp table if somehow exists, copy client table with all metadata then copy all data
    session.execute("DROP TABLE IF EXISTS migration_client;")
    session.execute("CREATE TABLE migration_client (LIKE client INCLUDING ALL);")
    session.execute("INSERT INTO migration_client SELECT * FROM client;")

    for client in session.query(MigrationClient).all():
        if client.i18n_metadata:
            metadata = json.loads(client.i18n_metadata)
        else:
            metadata = {}

        if client.redirect_uri:
            metadata["redirect_uris"] = client.redirect_uri
        if client.token_endpoint_auth_method:
            metadata["token_endpoint_auth_method"] = client.token_endpoint_auth_method
        if client._allowed_scopes:
            metadata["scope"] = client._allowed_scopes.split(" ")
        if client.grant_type:
            metadata["grant_type"] = client.grant_type.splitlines()
        if client.response_type:
            metadata["response_type"] = client.response_type.splitlines()
        if client.client_uri:
            metadata["client_uri"] = client.client_uri
        if client.logo_uri:
            metadata["logo_uri"] = client.logo_uri
        if client.contact:
            metadata["contact"] = client.contact
        if client.contact:
            metadata["tos_uri"] = client.tos_uri
        if client.contact:
            metadata["policy_uri"] = client.policy_uri
        if client.contact:
            metadata["jwks_uri"] = client.jwks_uri
        if client.contact:
            metadata["jwks_text"] = client.jwks_text
        if client.contact:
            metadata["software_id"] = client.software_id
        if client.contact:
            metadata["software_version"] = client.software_version

        client._client_metadata = json_dumps(metadata)

    # Drop and recreate client Table, copy data and recreate Foreign Key, drop temp table
    op.drop_table("client")
    session.execute("CREATE TABLE client (LIKE migration_client INCLUDING ALL);")
    session.execute("INSERT INTO client SELECT * FROM migration_client;")
    op.create_foreign_key(
        "client_user_id_fk", "client", "User", ["user_id"], ["id"], ondelete="CASCADE"
    )
    session.commit()
    op.drop_table("migration_client")


def set_old_column_values():
    conn = op.get_bind()
    session = Session(bind=conn)

    # Drop temp table if somehow exists, copy client table with all metadata then copy all data
    session.execute("DROP TABLE IF EXISTS migration_client;")
    session.execute("CREATE TABLE migration_client (LIKE client INCLUDING ALL);")
    session.execute("INSERT INTO migration_client SELECT * FROM client;")

    # Data Transformation on temp table
    for client in session.query(MigrationClient).all():
        if client._client_metadata:
            metadata = json_loads(client._client_metadata)
            client.i18n_metadata = metadata

        if metadata:
            if "redirect_uris" in metadata:
                client.redirect_uri = metadata["redirect_uris"]
            if "token_endpoint_auth_method" in metadata:
                client.token_endpoint_auth_method = metadata[
                    "token_endpoint_auth_method"
                ]
            if "_allowed_scopes" in metadata:
                client._allowed_scopes = " ".join(metadata["scope"])
            if "grant_type" in metadata:
                client.grant_type = "\n".joinmetadata["grant_type"]
            if "response_type" in metadata:
                client.response_type = "\n".join(metadata["response_type"])
            if "client_uri" in metadata:
                client.client_uri = metadata["client_uri"]
            if "logo_uri" in metadata:
                client.logo_uri = metadata["logo_uri"]
            if "contact" in metadata:
                client.contact = metadata["contact"]
            if "tos_uri" in metadata:
                client.tos_uri = metadata["tos_uri"]
            if "policy_uri" in metadata:
                client.policy_uri = metadata["policy_uri"]
            if "jwks_uri" in metadata:
                client.jwks_uri = metadata["jwks_uri"]
            if "jwks_text" in metadata:
                client.jwks_text = metadata["jwks_text"]
            if "software_id" in metadata:
                client.software_id = metadata["software_id"]
            if "software_version" in metadata:
                client.software_version = metadata["software_version"]

    # Drop and recreate client Table, copy data and recreate Foreign Key, drop temp table
    op.drop_table("client")
    session.execute("CREATE TABLE client (LIKE migration_client INCLUDING ALL);")
    session.execute("INSERT INTO client SELECT * FROM migration_client;")
    op.create_foreign_key(
        "client_user_id_fk", "client", "User", ["user_id"], ["id"], ondelete="CASCADE"
    )
    session.commit()
    op.drop_table("migration_client")
