"""authlib update 1.2.1

Revision ID: 9b3a5a7145d7
Revises: a04a70296688
Create Date: 2023-09-01 10:27:16.686456

"""
from alembic import op
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


def upgrade():

    # Make a copy of client table
    copy_client_to_temp_and_clear_data(op)

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
    op.drop_table("migration_client")

    # Add New Columns for authorization_code Table
    op.add_column(
        "authorization_code", sa.Column("code_challenge", sa.Text(), nullable=True)
    )
    op.add_column(
        "authorization_code",
        sa.Column("code_challenge_method", sa.String(length=48), nullable=True),
    )


def downgrade():

    # Make a copy of client table
    copy_client_to_temp_and_clear_data(op)

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
    op.drop_table("migration_client")

    # Remove New Columns for authorization_code Table
    op.drop_column("authorization_code", "code_challenge")
    op.drop_column("authorization_code", "code_challenge_method")


def copy_client_to_temp_and_clear_data(op):
    conn = op.get_bind()
    session = Session(bind=conn)
    # Drop temp table if somehow exists, copy client table with all metadata then copy all data
    session.execute("DROP TABLE IF EXISTS migration_client;")
    session.execute("CREATE TABLE migration_client (LIKE client INCLUDING ALL);")
    session.execute("INSERT INTO migration_client SELECT * FROM client;")
    session.execute("Truncate client")
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
            metadata["redirect_uris"] = client.redirect_uri
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

    rs = session.execute("SELECT * FROM migration_client")
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

        if "redirect_uris" in metadata:
            data["redirect_uri"] = metadata["redirect_uris"]
        else:
            data["redirect_uri"] = None

        if "token_endpoint_auth_method" in metadata:
            data["token_endpoint_auth_method"] = metadata["token_endpoint_auth_method"]
        else:
            data["token_endpoint_auth_method"] = None

        if "scope" in metadata:
            data["_allowed_scopes"] = metadata["scope"]
        else:
            data["_allowed_scopes"] = None

        if "grant_types" in metadata and metadata["grant_types"]:
            data["grant_type"] = "\n".join(metadata["grant_types"])
        else:
            data["grant_type"] = ""

        if "response_types" in metadata and metadata["response_types"]:
            data["response_type"] = "\n".join(metadata["response_types"])
        else:
            data["response_type"] = ""

        if "client_uri" in metadata:
            data.client_uri = metadata["client_uri"]
        else:
            data["client_uri"] = None

        if "logo_uri" in metadata:
            data["logo_uri"] = metadata["logo_uri"]
        else:
            data["logo_uri"] = None

        if "contact" in metadata:
            data["contact"] = metadata["contact"]
        else:
            data["contact"] = None

        if "tos_uri" in metadata:
            data["tos_uri"] = metadata["tos_uri"]
        else:
            data["tos_uri"] = None

        if "policy_uri" in metadata:
            data["policy_uri"] = metadata["policy_uri"]
        else:
            data["policy_uri"] = None

        if "jwks_uri" in metadata:
            data["jwks_uri"] = metadata["jwks_uri"]
        else:
            data["jwks_uri"] = None

        if "jwks_text" in metadata:
            data["jwks_text"] = metadata["jwks_text"]
        else:
            data["jwks_text"] = None

        if "software_id" in metadata:
            data["software_id"] = metadata["software_id"]
        else:
            data["software_id"] = None

        if "software_version" in metadata:
            data["software_version"] = metadata["software_version"]
        else:
            data["software_version"] = None

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
