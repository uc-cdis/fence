"""authlib update 1.2.1

Revision ID: 9b3a5a7145d7
Revises: a04a70296688
Create Date: 2023-09-01 10:27:16.686456

"""

from alembic import op
import logging
import sqlalchemy as sa
from sqlalchemy.orm import Session
from sqlalchemy.sql import text

import json
from authlib.common.encoding import json_loads, json_dumps

from migrations.models.migration_client import MigrationClient
from fence.models import Client

# revision identifiers, used by Alembic.
revision = "9b3a5a7145d7"  # pragma: allowlist secret
down_revision = "a04a70296688"  # pragma: allowlist secret
branch_labels = None
depends_on = None

logger = logging.getLogger("fence.alembic")


def upgrade():
    # Remove google_service_account_client_id_fkey if it exists
    remove_foreign_key_constraint_if_exists(op)
    temp_table_name = "migration_client"
    # Make a copy of client table
    copy_client_to_temp_table_and_clear_data(op, temp_table_name)

    # Add new columns for client table
    op.add_column("client", sa.Column("client_metadata", sa.Text(), nullable=True))
    op.add_column(
        "client",
        sa.Column(
            "client_secret_expires_at", sa.Integer(), nullable=False, server_default="0"
        ),
    )

    # Modify columns for client table
    op.alter_column("client", "issued_at", new_column_name="client_id_issued_at")
    op.alter_column("client", "client_id", nullable=False, type_=sa.String(48))
    op.alter_column("client", "client_secret", nullable=True, type_=sa.String(120))

    # Delete old columns for client table
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

    transform_client_data(op)

    # Drop temp table
    op.drop_table(temp_table_name)

    # Add New Columns for authorization_code Table
    op.add_column(
        "authorization_code", sa.Column("code_challenge", sa.Text(), nullable=True)
    )
    op.add_column(
        "authorization_code",
        sa.Column("code_challenge_method", sa.String(length=48), nullable=True),
    )


def downgrade():

    temp_table_name = "migration_client"
    # Make a copy of client table
    copy_client_to_temp_table_and_clear_data(op, temp_table_name)

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

    # Modify Columns for client Table
    op.alter_column("client", "client_id_issued_at", new_column_name="issued_at")
    op.alter_column("client", "client_id", nullable=False, type_=sa.String(40))
    op.alter_column("client", "client_secret", nullable=True, type_=sa.String(60))

    # Drop New Columns for client Table
    op.drop_column("client", "client_metadata")
    op.drop_column("client", "client_secret_expires_at")

    # Set value of old columns
    set_old_column_values()
    op.drop_table(temp_table_name)

    # Remove New Columns for authorization_code Table
    op.drop_column("authorization_code", "code_challenge")
    op.drop_column("authorization_code", "code_challenge_method")


def copy_client_to_temp_table_and_clear_data(op, temp_table_name: str):
    """Copy client table schema and data into temp table"""
    conn = op.get_bind()
    session = Session(bind=conn)
    # Drop temp table if it already exists
    # copy client table with all table metadata then copy all row data
    session.execute(text(f"DROP TABLE IF EXISTS {temp_table_name}"))
    session.execute(text(f"CREATE TABLE {temp_table_name} (LIKE client INCLUDING ALL)"))
    session.execute(text(f"INSERT INTO {temp_table_name} SELECT * FROM client"))
    session.execute(text("Truncate client"))
    session.commit()


def transform_client_data(op):
    conn = op.get_bind()
    session = Session(bind=conn)

    for client in session.query(MigrationClient).all():
        if client.i18n_metadata:
            metadata = json.loads(client.i18n_metadata)
        else:
            metadata = {}

        if client.redirect_uri:
            metadata["redirect_uris"] = client.redirect_uri.splitlines()
        if client.token_endpoint_auth_method:
            metadata["token_endpoint_auth_method"] = client.token_endpoint_auth_method
        if client.grant_type:
            metadata["grant_types"] = client.grant_type.splitlines()
        if client.response_type:
            metadata["response_types"] = client.response_type.splitlines()
        if client.client_uri:
            metadata["client_uri"] = client.client_uri
        if client.logo_uri:
            metadata["logo_uri"] = client.logo_uri
        if client.contact:
            metadata["contact"] = client.contact
        if client.tos_uri:
            metadata["tos_uri"] = client.tos_uri
        if client.policy_uri:
            metadata["policy_uri"] = client.policy_uri
        if client.jwks_uri:
            metadata["jwks_uri"] = client.jwks_uri
        if client.jwks_text:
            metadata["jwks_text"] = client.jwks_text
        if client.software_id:
            metadata["software_id"] = client.software_id
        if client.software_version:
            metadata["software_version"] = client.software_version

        new_client = Client(
            client_id=client.client_id,
            client_secret=client.client_secret,
            name=client.name,
            description=client.description,
            allowed_scopes=client._allowed_scopes.split(" "),
            user_id=client.user_id,
            auto_approve=client.auto_approve,
            is_confidential=client.is_confidential,
            expires_at=client.expires_at,
            _default_scopes=client._default_scopes,
            grant_types=client.grant_type.splitlines(),
            response_types=client.response_type.splitlines(),
            client_id_issued_at=client.issued_at,
            _client_metadata=json_dumps(metadata),
        )

        session.add(new_client)

    session.commit()


def set_old_column_values():
    conn = op.get_bind()
    session = Session(bind=conn)
    clientDatas = []

    rs = session.execute(text("SELECT * FROM migration_client"))
    for client in rs:
        data = {}
        data["client_id"] = client.client_id
        data["client_secret"] = client.client_secret
        data["name"] = client.name
        data["description"] = client.description
        data["user_id"] = client.user_id
        data["auto_approve"] = client.auto_approve
        data["is_confidential"] = client.is_confidential
        data["expires_at"] = client.expires_at
        data["issued_at"] = client.client_id_issued_at
        data["_default_scopes"] = client._default_scopes
        data["_redirect_uris"] = None  # Deprecated
        data["scope"] = ""  # Deprecated
        data["client_name"] = None

        if client.client_metadata:
            metadata = json_loads(client.client_metadata)
            data["i18n_metadata"] = client.client_metadata
        else:
            metadata = {}
            data["i18n_metadata"] = None

        if metadata.get("redirect_uris"):
            data["redirect_uri"] = "\n".join(
                [item for item in metadata.get("redirect_uris") if item]
            )
        else:
            data["redirect_uri"] = ""

        data["token_endpoint_auth_method"] = metadata.get("token_endpoint_auth_method")
        data["_allowed_scopes"] = metadata.get("scope")

        if metadata.get("grant_types"):
            data["grant_type"] = "\n".join(
                [item for item in metadata.get("grant_types") if item]
            )
        else:
            data["grant_type"] = ""

        if metadata.get("response_types"):
            data["response_type"] = "\n".join(
                [item for item in metadata.get("response_types") if item]
            )
        else:
            data["response_type"] = ""

        data["client_uri"] = metadata.get("client_uri")
        data["logo_uri"] = metadata.get("logo_uri")
        data["contact"] = metadata.get("contact")
        data["tos_uri"] = metadata.get("tos_uri")
        data["policy_uri"] = metadata.get("policy_uri")
        data["jwks_uri"] = metadata.get("jwks_uri")
        data["jwks_text"] = metadata.get("jwks_text")
        data["software_id"] = metadata.get("software_id")
        data["software_version"] = metadata.get("software_version")

        clientDatas.append(data)

    statement = text(
        """INSERT INTO client(client_id, client_secret, name, description,
        user_id, auto_approve, is_confidential, issued_at, expires_at, _redirect_uris, _allowed_scopes,
        _default_scopes, redirect_uri, token_endpoint_auth_method, grant_type, response_type, scope,
        client_name,client_uri,logo_uri,contact,tos_uri,policy_uri,jwks_uri,jwks_text,i18n_metadata,
        software_id,software_version)
        VALUES( :client_id, :client_secret, :name, :description, :user_id, :auto_approve, :is_confidential, :issued_at,
            :expires_at, :_redirect_uris, :_allowed_scopes, :_default_scopes, :redirect_uri, :token_endpoint_auth_method,
            :grant_type, :response_type, :scope, :client_name, :client_uri, :logo_uri, :contact, :tos_uri, :policy_uri,
            :jwks_uri, :jwks_text, :i18n_metadata, :software_id, :software_version)"""
    )

    for data in clientDatas:
        conn.execute(statement, **data)

    session.commit()


def remove_foreign_key_constraint_if_exists(op):
    """
    Pre-alembic era created a foreign key clent_id(from the client table) on the google_service_account table.
    This foreign key was then removed from the schema but any commons created before the constraint was removed
    still held the foreign key.
    The previous alembic migration tuncates the client table but this fails if the foreign key constraint still persists
    therefore failing the migration.
    This migration checks for the existence of the foreign key constraint and removes it if it exists.
    There is no downgrade path for this since not having the foreign key constraint is the correct schema throughout all versions.
    This migration is specifically for commons that were created before the foreign key constraint was removed
    """
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    foreign_keys = inspector.get_foreign_keys("google_service_account")
    fk_exists = False
    for fk in foreign_keys:
        if "client_id" in fk["constrained_columns"]:
            fk_exists = True

    if fk_exists:
        logger.info("Foreign key client_id exists. Removing constraint...")
        op.drop_constraint(
            "google_service_account_client_id_fkey",
            "google_service_account",
            type_="foreignkey",
        )
    else:
        logger.debug(
            "Foreign key client_id does not exist. This is expected for newer versions of the service."
        )
