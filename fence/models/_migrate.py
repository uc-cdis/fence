"""
The `migrate` function in this file is called every init and can be used for
database migrations.
"""
from sqlalchemy import Table
from sqlalchemy import MetaData

from fence.jwt.token import CLIENT_ALLOWED_SCOPES

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
