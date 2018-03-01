"""
The `migrate` function in this file is called every init and can be used for
database migrations.
"""
from sqlalchemy import Table
from sqlalchemy import MetaData
from sqlalchemy.schema import ForeignKey
from sqlalchemy import String

from fence.jwt.token import CLIENT_ALLOWED_SCOPES

from fence.models.users import User
from fence.models.cloud_resources import GoogleProxyGroup
from fence.models.cloud_resources import GoogleServiceAccount
from fence.models.auth import Client
from fence.models.creds import UserRefreshToken


to_timestamp = "CREATE OR REPLACE FUNCTION pc_datetime_to_timestamp(datetoconvert timestamp) " \
               "RETURNS BIGINT AS " \
               "$BODY$ " \
               "select extract(epoch from $1)::BIGINT " \
               "$BODY$ " \
               "LANGUAGE 'sql' IMMUTABLE STRICT;"


def migrate(driver):
    if not driver.engine.dialect.supports_alter:
        print("This engine dialect doesn't support altering so we are not migrating even if necessary!")
        return

    md = MetaData()

    table = Table(UserRefreshToken.__tablename__, md, autoload=True, autoload_with=driver.engine)
    if str(table.c.expires.type) != 'BIGINT':
        print("Altering table %s expires to BIGINT" % (UserRefreshToken.__tablename__))
        with driver.session as session:
            session.execute(to_timestamp)
        with driver.session as session:
            session.execute("ALTER TABLE {} ALTER COLUMN expires TYPE BIGINT USING pc_datetime_to_timestamp(expires);".format(UserRefreshToken.__tablename__))

    # oidc migration

    table = Table(Client.__tablename__, md, autoload=True, autoload_with=driver.engine)
    if not any([index.name == 'ix_name' for index in table.indexes]):
        with driver.session as session:
            session.execute(
                "ALTER TABLE {} ADD constraint ix_name unique (name);"
                .format(Client.__tablename__)
            )

    if '_allowed_scopes' not in table.c:
        print(
            "Altering table {} to add _allowed_scopes column"
            .format(Client.__tablename__)
        )
        with driver.session as session:
            session.execute(
                "ALTER TABLE {} ADD COLUMN _allowed_scopes VARCHAR;"
                .format(Client.__tablename__)
            )
            for client in session.query(Client):
                if not client._allowed_scopes:
                    client._allowed_scopes = ' '.join(CLIENT_ALLOWED_SCOPES)
                    session.add(client)
            session.commit()
            session.execute(
                "ALTER TABLE {} ALTER COLUMN _allowed_scopes SET NOT NULL;"
                .format(Client.__tablename__)
            )

    add_column_if_not_exist(
        table_name=GoogleProxyGroup.__tablename__,
        column_name='email',
        column_type=String,
        driver=driver,
        metadata=md
    )

    drop_foreign_key_column_if_exist(
        table_name=GoogleProxyGroup.__tablename__,
        column_name='user_id',
        driver=driver,
        metadata=md
    )

    add_foreign_key_column_if_not_exist(
        table_name=User.__tablename__,
        column_name='google_proxy_group_id',
        column_type=String(90),
        fk_table_name=GoogleProxyGroup.__tablename__,
        fk_column_name='id',
        driver=driver,
        metadata=md
    )

    drop_foreign_key_constraint_if_exist(
        table_name=GoogleServiceAccount.__tablename__,
        column_name='client_id',
        driver=driver,
        metadata=md
    )


def add_foreign_key_column_if_not_exist(
        table_name, column_name, column_type, fk_table_name, fk_column_name, driver,
        metadata):
    add_column_if_not_exist(
        table_name, column_name, column_type, driver, metadata)
    add_foreign_key_constraint_if_not_exist(
        table_name, column_name, fk_table_name, fk_column_name, driver,
        metadata)


def drop_foreign_key_column_if_exist(table_name, column_name, driver, metadata):
    drop_foreign_key_constraint_if_exist(
        table_name, column_name, driver, metadata)
    drop_column_if_exist(table_name, column_name, driver, metadata)


def add_column_if_not_exist(
        table_name, column_name, column_type, driver, metadata):
    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)
    if column_name not in table.c:
        with driver.session as session:
            session.execute(
                "ALTER TABLE \"{}\" ADD COLUMN {} {};"
                .format(table_name, column_name, column_type)
            )
            session.commit()


def drop_column_if_exist(table_name, column_name, driver, metadata):
    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)
    if column_name in table.c:
        with driver.session as session:
            session.execute(
                "ALTER TABLE \"{}\" DROP COLUMN {};"
                .format(table_name, column_name)
            )
            session.commit()


def add_foreign_key_constraint_if_not_exist(
        table_name, column_name, fk_table_name, fk_column_name,
        driver, metadata):
    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)
    foreign_key_name = "{}_{}_fkey".format(table_name.lower(), column_name)

    if column_name in table.c:
        foreign_keys = [fk.name for fk in getattr(table.c, column_name).foreign_keys]
        if foreign_key_name not in foreign_keys:
            with driver.session as session:
                session.execute(
                    "ALTER TABLE \"{}\" ADD CONSTRAINT {} "
                    "FOREIGN KEY({}) REFERENCES {} ({});"
                    .format(
                        table_name, foreign_key_name, column_name,
                        fk_table_name, fk_column_name
                    )
                )
                session.commit()


def drop_foreign_key_constraint_if_exist(
        table_name, column_name, driver, metadata):
    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)
    foreign_key_name = "{}_{}_fkey".format(table_name.lower(), column_name)

    if column_name in table.c:
        foreign_keys = [fk.name for fk in getattr(table.c, column_name).foreign_keys]
        if foreign_key_name in foreign_keys:
            with driver.session as session:
                session.execute(
                    "ALTER TABLE \"{}\" DROP CONSTRAINT {};"
                    .format(table_name, foreign_key_name)
                )
                session.commit()
