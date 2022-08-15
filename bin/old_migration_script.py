"""
This script contains the database migrations written BEFORE switching to
Alembic for migrations. We need to keep it around to migrate databases from a
pre-Alembic version to a post-Alembic version.

DO NOT ADD NEW MIGRATIONS TO THIS SCRIPT.
Create a new Alembic revision instead.
"""


from sqlalchemy import (
    Integer,
    BigInteger,
    DateTime,
    String,
    Column,
    Text,
    MetaData,
    Table,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy import exc as sa_exc, func
import warnings

from fence.config import config
from fence.models import (
    AuthorizationCode,
    Client,
    GoogleBucketAccessGroup,
    GoogleProxyGroup,
    GoogleProxyGroupToGoogleBucketAccessGroup,
    GoogleServiceAccount,
    Project,
    User,
    UserRefreshToken,
)

to_timestamp = (
    "CREATE OR REPLACE FUNCTION pc_datetime_to_timestamp(datetoconvert timestamp) "
    "RETURNS BIGINT AS "
    "$BODY$ "
    "select extract(epoch from $1)::BIGINT "
    "$BODY$ "
    "LANGUAGE 'sql' IMMUTABLE STRICT;"
)


def migrate(driver):
    if not driver.engine.dialect.supports_alter:
        print(
            "This engine dialect doesn't support altering so we are not migrating even if necessary!"
        )
        return

    md = MetaData()

    table = Table(
        UserRefreshToken.__tablename__, md, autoload=True, autoload_with=driver.engine
    )
    if str(table.c.expires.type) != "BIGINT":
        print("Altering table %s expires to BIGINT" % (UserRefreshToken.__tablename__))
        with driver.session as session:
            session.execute(to_timestamp)
        with driver.session as session:
            session.execute(
                "ALTER TABLE {} ALTER COLUMN expires TYPE BIGINT USING pc_datetime_to_timestamp(expires);".format(
                    UserRefreshToken.__tablename__
                )
            )

    # username limit migration

    table = Table(User.__tablename__, md, autoload=True, autoload_with=driver.engine)
    if str(table.c.username.type) != str(User.username.type):
        print(
            "Altering table %s column username type to %s"
            % (User.__tablename__, str(User.username.type))
        )
        with driver.session as session:
            session.execute(
                'ALTER TABLE "{}" ALTER COLUMN username TYPE {};'.format(
                    User.__tablename__, str(User.username.type)
                )
            )

    # oidc migration

    table = Table(Client.__tablename__, md, autoload=True, autoload_with=driver.engine)
    if not ("ix_name" in [constraint.name for constraint in table.constraints]):
        with driver.session as session:
            session.execute(
                "ALTER TABLE {} ADD constraint ix_name unique (name);".format(
                    Client.__tablename__
                )
            )

    if "_allowed_scopes" not in table.c:
        print(
            "Altering table {} to add _allowed_scopes column".format(
                Client.__tablename__
            )
        )
        with driver.session as session:
            session.execute(
                "ALTER TABLE {} ADD COLUMN _allowed_scopes VARCHAR;".format(
                    Client.__tablename__
                )
            )
            for client in session.query(Client):
                if not client._allowed_scopes:
                    client._allowed_scopes = " ".join(config["CLIENT_ALLOWED_SCOPES"])
                    session.add(client)
            session.commit()
            session.execute(
                "ALTER TABLE {} ALTER COLUMN _allowed_scopes SET NOT NULL;".format(
                    Client.__tablename__
                )
            )

    add_column_if_not_exist(
        table_name=GoogleProxyGroup.__tablename__,
        column=Column("email", String),
        driver=driver,
        metadata=md,
    )

    add_column_if_not_exist(
        table_name=AuthorizationCode.__tablename__,
        column=Column("refresh_token_expires_in", Integer),
        driver=driver,
        metadata=md,
    )

    drop_foreign_key_column_if_exist(
        table_name=GoogleProxyGroup.__tablename__,
        column_name="user_id",
        driver=driver,
        metadata=md,
    )

    _add_google_project_id(driver, md)

    drop_unique_constraint_if_exist(
        table_name=GoogleServiceAccount.__tablename__,
        column_name="google_unique_id",
        driver=driver,
        metadata=md,
    )

    drop_unique_constraint_if_exist(
        table_name=GoogleServiceAccount.__tablename__,
        column_name="google_project_id",
        driver=driver,
        metadata=md,
    )

    add_column_if_not_exist(
        table_name=GoogleBucketAccessGroup.__tablename__,
        column=Column("privileges", ARRAY(String)),
        driver=driver,
        metadata=md,
    )

    _update_for_authlib(driver, md)

    # Delete-user migration

    # Check if at least one constraint is already migrated and if so skip
    # the delete cascade migration.
    user = Table(User.__tablename__, md, autoload=True, autoload_with=driver.engine)
    found_user_constraint_already_migrated = False

    for fkey in list(user.foreign_key_constraints):
        if (
            len(fkey.column_keys) == 1
            and "google_proxy_group_id" in fkey.column_keys
            and fkey.ondelete == "SET NULL"
        ):
            found_user_constraint_already_migrated = True

    if not found_user_constraint_already_migrated:
        # do delete user migration in one session
        delete_user_session = driver.Session()
        try:
            # Deleting google proxy group shouldn't delete user
            set_foreign_key_constraint_on_delete_setnull(
                table_name=User.__tablename__,
                column_name="google_proxy_group_id",
                fk_table_name=GoogleProxyGroup.__tablename__,
                fk_column_name="id",
                driver=driver,
                session=delete_user_session,
                metadata=md,
            )

            _set_on_delete_cascades(driver, delete_user_session, md)

            delete_user_session.commit()
        except Exception:
            delete_user_session.rollback()
            raise
        finally:
            delete_user_session.close()

    _remove_policy(driver, md)

    add_column_if_not_exist(
        table_name=User.__tablename__,
        column=Column(
            "_last_auth", DateTime(timezone=False), server_default=func.now()
        ),
        driver=driver,
        metadata=md,
    )

    add_column_if_not_exist(
        table_name=User.__tablename__,
        column=Column("additional_info", JSONB(), server_default=text("'{}'")),
        driver=driver,
        metadata=md,
    )

    with driver.session as session:
        session.execute(
            """\
CREATE OR REPLACE FUNCTION process_user_audit() RETURNS TRIGGER AS $user_audit$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            INSERT INTO user_audit_logs (timestamp, operation, old_values)
            SELECT now(), 'DELETE', row_to_json(OLD);
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            INSERT INTO user_audit_logs (timestamp, operation, old_values, new_values)
            SELECT now(), 'UPDATE', row_to_json(OLD), row_to_json(NEW);
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            INSERT INTO user_audit_logs (timestamp, operation, new_values)
            SELECT now(), 'INSERT', row_to_json(NEW);
            RETURN NEW;
        END IF;
        RETURN NULL;
    END;
$user_audit$ LANGUAGE plpgsql;"""
        )

        exist = session.scalar(
            "SELECT exists (SELECT * FROM pg_trigger WHERE tgname = 'user_audit')"
        )
        session.execute(
            ('DROP TRIGGER user_audit ON "User"; ' if exist else "")
            + """\
CREATE TRIGGER user_audit
AFTER INSERT OR UPDATE OR DELETE ON "User"
    FOR EACH ROW EXECUTE PROCEDURE process_user_audit();"""
        )

        session.execute(
            """\
CREATE OR REPLACE FUNCTION process_cert_audit() RETURNS TRIGGER AS $cert_audit$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            INSERT INTO cert_audit_logs (timestamp, operation, user_id, username, old_values)
            SELECT now(), 'DELETE', "User".id, "User".username, row_to_json(OLD)
            FROM application INNER JOIN "User" ON application.user_id = "User".id
            WHERE OLD.application_id = application.id;
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            INSERT INTO cert_audit_logs (timestamp, operation, user_id, username, old_values, new_values)
            SELECT now(), 'UPDATE', "User".id, "User".username, row_to_json(OLD), row_to_json(NEW)
            FROM application INNER JOIN "User" ON application.user_id = "User".id
            WHERE NEW.application_id = application.id;
            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            INSERT INTO cert_audit_logs (timestamp, operation, user_id, username, new_values)
            SELECT now(), 'INSERT', "User".id, "User".username, row_to_json(NEW)
            FROM application INNER JOIN "User" ON application.user_id = "User".id
            WHERE NEW.application_id = application.id;
            RETURN NEW;
        END IF;
        RETURN NULL;
    END;
$cert_audit$ LANGUAGE plpgsql;"""
        )

        exist = session.scalar(
            "SELECT exists (SELECT * FROM pg_trigger WHERE tgname = 'cert_audit')"
        )
        session.execute(
            ("DROP TRIGGER cert_audit ON certificate; " if exist else "")
            + """\
CREATE TRIGGER cert_audit
AFTER INSERT OR UPDATE OR DELETE ON certificate
    FOR EACH ROW EXECUTE PROCEDURE process_cert_audit();"""
        )

    # Google Access expiration

    add_column_if_not_exist(
        table_name=GoogleProxyGroupToGoogleBucketAccessGroup.__tablename__,
        column=Column("expires", BigInteger()),
        driver=driver,
        metadata=md,
    )

    add_column_if_not_exist(
        table_name=Project.__tablename__,
        column=Column("authz", String),
        driver=driver,
        metadata=md,
    )


def add_foreign_key_column_if_not_exist(
    table_name,
    column_name,
    column_type,
    fk_table_name,
    fk_column_name,
    driver,
    metadata,
):
    column = Column(column_name, column_type)
    add_column_if_not_exist(table_name, column, driver, metadata)
    add_foreign_key_constraint_if_not_exist(
        table_name, column_name, fk_table_name, fk_column_name, driver, metadata
    )


def drop_foreign_key_column_if_exist(table_name, column_name, driver, metadata):
    drop_foreign_key_constraint_if_exist(table_name, column_name, driver, metadata)
    drop_column_if_exist(table_name, column_name, driver, metadata)


def add_column_if_not_exist(table_name, column, driver, metadata, default=None):
    column_name = column.compile(dialect=driver.engine.dialect)
    column_type = column.type.compile(driver.engine.dialect)

    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    if str(column_name) not in table.c:
        with driver.session as session:
            command = 'ALTER TABLE "{}" ADD COLUMN {} {}'.format(
                table_name, column_name, column_type
            )
            if not column.nullable:
                command += " NOT NULL"
            if getattr(column, "default"):
                default = column.default.arg
                if isinstance(default, str):
                    default = "'{}'".format(default)
                command += " DEFAULT {}".format(default)
            command += ";"

            session.execute(command)
            session.commit()


def drop_column_if_exist(table_name, column_name, driver, metadata):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    if column_name in table.c:
        with driver.session as session:
            session.execute(
                'ALTER TABLE "{}" DROP COLUMN {};'.format(table_name, column_name)
            )
            session.commit()


def add_foreign_key_constraint_if_not_exist(
    table_name, column_name, fk_table_name, fk_column_name, driver, metadata
):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    foreign_key_name = "{}_{}_fkey".format(table_name.lower(), column_name)

    if column_name in table.c:
        foreign_keys = [fk.name for fk in getattr(table.c, column_name).foreign_keys]
        if foreign_key_name not in foreign_keys:
            with driver.session as session:
                session.execute(
                    'ALTER TABLE "{}" ADD CONSTRAINT {} '
                    'FOREIGN KEY({}) REFERENCES "{}" ({});'.format(
                        table_name,
                        foreign_key_name,
                        column_name,
                        fk_table_name,
                        fk_column_name,
                    )
                )
                session.commit()


def set_foreign_key_constraint_on_delete_cascade(
    table_name, column_name, fk_table_name, fk_column_name, driver, session, metadata
):
    set_foreign_key_constraint_on_delete(
        table_name,
        column_name,
        fk_table_name,
        fk_column_name,
        "CASCADE",
        driver,
        session,
        metadata,
    )


def set_foreign_key_constraint_on_delete_setnull(
    table_name, column_name, fk_table_name, fk_column_name, driver, session, metadata
):
    set_foreign_key_constraint_on_delete(
        table_name,
        column_name,
        fk_table_name,
        fk_column_name,
        "SET NULL",
        driver,
        session,
        metadata,
    )


def set_foreign_key_constraint_on_delete(
    table_name,
    column_name,
    fk_table_name,
    fk_column_name,
    ondelete,
    driver,
    session,
    metadata,
):
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Predicate of partial index \S+ ignored during reflection",
            category=sa_exc.SAWarning,
        )
        table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    foreign_key_name = "{}_{}_fkey".format(table_name.lower(), column_name)

    if column_name in table.c:
        session.execute(
            'ALTER TABLE ONLY "{}" DROP CONSTRAINT IF EXISTS {}, '
            'ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES "{}" ({}) ON DELETE {};'.format(
                table_name,
                foreign_key_name,
                foreign_key_name,
                column_name,
                fk_table_name,
                fk_column_name,
                ondelete,
            )
        )


def drop_foreign_key_constraint_if_exist(table_name, column_name, driver, metadata):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    foreign_key_name = "{}_{}_fkey".format(table_name.lower(), column_name)

    if column_name in table.c:
        foreign_keys = [fk.name for fk in getattr(table.c, column_name).foreign_keys]
        if foreign_key_name in foreign_keys:
            with driver.session as session:
                session.execute(
                    'ALTER TABLE "{}" DROP CONSTRAINT {};'.format(
                        table_name, foreign_key_name
                    )
                )
                session.commit()


def add_unique_constraint_if_not_exist(table_name, column_name, driver, metadata):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    index_name = "{}_{}_key".format(table_name, column_name)

    if column_name in table.c:
        indexes = [index.name for index in table.indexes]

        if index_name not in indexes:
            with driver.session as session:
                session.execute(
                    'ALTER TABLE "{}" ADD CONSTRAINT {} UNIQUE ({});'.format(
                        table_name, index_name, column_name
                    )
                )
                session.commit()


def drop_unique_constraint_if_exist(table_name, column_name, driver, metadata):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    constraint_name = "{}_{}_key".format(table_name, column_name)

    if column_name in table.c:
        constraints = [
            constaint.name for constaint in getattr(table.c, column_name).constraints
        ]

        unique_index = None
        for index in table.indexes:
            if index.name == constraint_name:
                unique_index = index

        if constraint_name in constraints or unique_index:
            with driver.session as session:
                session.execute(
                    'ALTER TABLE "{}" DROP CONSTRAINT {};'.format(
                        table_name, constraint_name
                    )
                )
                session.commit()


def drop_default_value(table_name, column_name, driver, metadata):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)

    if column_name in table.c:
        with driver.session as session:
            session.execute(
                'ALTER TABLE "{}" ALTER COLUMN "{}" DROP DEFAULT;'.format(
                    table_name, column_name
                )
            )
            session.commit()


def add_not_null_constraint(table_name, column_name, driver, metadata):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)

    if column_name in table.c:
        with driver.session as session:
            session.execute(
                'ALTER TABLE "{}" ALTER COLUMN "{}" SET NOT NULL;'.format(
                    table_name, column_name
                )
            )
            session.commit()


def _remove_policy(driver, md):
    with driver.session as session:
        session.execute("DROP TABLE IF EXISTS users_to_policies;")
        session.execute("DROP TABLE IF EXISTS policy;")
        session.commit()


def _add_google_project_id(driver, md):
    """
    Add new unique not null field to GoogleServiceAccount.
    In order to do this without errors, we have to:
        - add the field and allow null (for all previous rows)
        - update all null entries to be unique
            - at the moment this is just for dev environments since we don't
              have anything in production. thus, these nonsense values will
              be sufficient
            - new additions of GoogleServiceAccounts will require this field
              to be not null and unique
        - add unique constraint
        - add not null constraint
    """
    # add new google_project_id column
    add_column_if_not_exist(
        table_name=GoogleServiceAccount.__tablename__,
        column=Column("google_project_id", String),
        driver=driver,
        metadata=md,
    )

    # make rows have unique values for new column
    with driver.session as session:
        rows_to_make_unique = session.query(GoogleServiceAccount).filter(
            GoogleServiceAccount.google_project_id.is_(None)
        )
        count = 0
        for row in rows_to_make_unique:
            row.google_project_id = count
            count += 1
    session.commit()

    # add not null constraint
    add_not_null_constraint(
        table_name=GoogleServiceAccount.__tablename__,
        column_name="google_project_id",
        driver=driver,
        metadata=md,
    )


def _update_for_authlib(driver, md):
    """
    Going to authlib=0.9, the OAuth2ClientMixin from authlib, which the client model
    inherits from, adds these new columns, some of which were added directly to the
    client model in order to override some things like nullability.
    """
    CLIENT_COLUMNS_TO_ADD = [
        Column("issued_at", Integer),
        Column("expires_at", Integer, nullable=False, default=0),
        Column("redirect_uri", Text, nullable=False, default=""),
        Column(
            "token_endpoint_auth_method",
            String(48),
            default="client_secret_basic",
            server_default="client_secret_basic",
        ),
        Column("grant_type", Text, nullable=False, default=""),
        Column("response_type", Text, nullable=False, default=""),
        Column("scope", Text, nullable=False, default=""),
        Column("client_name", String(100)),
        Column("client_uri", Text),
        Column("logo_uri", Text),
        Column("contact", Text),
        Column("tos_uri", Text),
        Column("policy_uri", Text),
        Column("jwks_uri", Text),
        Column("jwks_text", Text),
        Column("i18n_metadata", Text),
        Column("software_id", String(36)),
        Column("software_version", String(48)),
    ]
    add_client_col = lambda col: add_column_if_not_exist(
        Client.__tablename__, column=col, driver=driver, metadata=md
    )
    list(map(add_client_col, CLIENT_COLUMNS_TO_ADD))
    CODE_COLUMNS_TO_ADD = [Column("response_type", Text, default="")]

    with driver.session as session:
        for client in session.query(Client).all():
            # add redirect_uri
            if not client.redirect_uri:
                redirect_uris = getattr(client, "_redirect_uris") or ""
                client.redirect_uri = "\n".join(redirect_uris.split())
            # add grant_type; everything prior to migration was just using code grant
            if not client.grant_type:
                client.grant_type = "authorization_code\nrefresh_token"
        session.commit()

    add_code_col = lambda col: add_column_if_not_exist(
        AuthorizationCode.__tablename__, column=col, driver=driver, metadata=md
    )
    list(map(add_code_col, CODE_COLUMNS_TO_ADD))
    with driver.session as session:
        session.execute("ALTER TABLE client ALTER COLUMN client_secret DROP NOT NULL")
        session.commit()

    # these ones are "manual"
    table = Table(
        AuthorizationCode.__tablename__, md, autoload=True, autoload_with=driver.engine
    )
    auth_code_columns = list(map(str, table.columns))
    tablename = AuthorizationCode.__tablename__
    # delete expires_at column
    if "{}.expires_at".format(tablename) in auth_code_columns:
        with driver.session as session:
            session.execute("ALTER TABLE {} DROP COLUMN expires_at;".format(tablename))
            session.commit()
    # add auth_time column
    if "{}.auth_time".format(tablename) not in auth_code_columns:
        with driver.session as session:
            command = "ALTER TABLE {} ADD COLUMN auth_time Integer NOT NULL DEFAULT extract(epoch from now());".format(
                tablename
            )
            session.execute(command)
            session.commit()
    # make sure modifiers on auth_time column are correct
    with driver.session as session:
        session.execute(
            "ALTER TABLE {} ALTER COLUMN auth_time SET NOT NULL;".format(tablename)
        )
        session.commit()
        session.execute(
            "ALTER TABLE {} ALTER COLUMN auth_time SET DEFAULT extract(epoch from now());".format(
                tablename
            )
        )
        session.commit()


def _set_on_delete_cascades(driver, session, md):
    set_foreign_key_constraint_on_delete_cascade(
        "client", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "authorization_code", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "google_service_account", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "user_google_account", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "user_google_account_to_proxy_group",
        "user_google_account_id",
        "user_google_account",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "user_google_account_to_proxy_group",
        "proxy_group_id",
        "google_proxy_group",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "google_service_account_key",
        "service_account_id",
        "google_service_account",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "google_bucket_access_group", "bucket_id", "bucket", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "google_proxy_group_to_google_bucket_access_group",
        "proxy_group_id",
        "google_proxy_group",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "google_proxy_group_to_google_bucket_access_group",
        "access_group_id",
        "google_bucket_access_group",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "service_account_access_privilege",
        "project_id",
        "project",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "service_account_access_privilege",
        "service_account_id",
        "user_service_account",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "service_account_to_google_bucket_access_group",
        "service_account_id",
        "user_service_account",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "service_account_to_google_bucket_access_group",
        "access_group_id",
        "google_bucket_access_group",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "hmac_keypair", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "hmac_keypair_archive", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "user_to_group", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "user_to_group", "group_id", "Group", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "access_privilege", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "access_privilege", "group_id", "Group", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "access_privilege", "project_id", "project", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "access_privilege",
        "provider_id",
        "authorization_provider",
        "id",
        driver,
        session,
        md,
    )
    set_foreign_key_constraint_on_delete_cascade(
        "user_to_bucket", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "user_to_bucket", "bucket_id", "bucket", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "bucket", "provider_id", "cloud_provider", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "project_to_bucket", "project_id", "project", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "project_to_bucket", "bucket_id", "bucket", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "compute_access", "project_id", "project", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "compute_access", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "compute_access", "group_id", "Group", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "compute_access", "provider_id", "cloud_provider", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "storage_access", "project_id", "project", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "storage_access", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "storage_access", "group_id", "Group", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "storage_access", "provider_id", "cloud_provider", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "certificate", "application_id", "application", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "s3credential", "user_id", "User", "id", driver, session, md
    )
    set_foreign_key_constraint_on_delete_cascade(
        "tag", "user_id", "User", "id", driver, session, md
    )
