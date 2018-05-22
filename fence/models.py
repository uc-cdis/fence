"""
Define sqlalchemy models.

The models here inherit from the `Base` in userdatamodel, so when the fence app
is initialized, the resulting db session includes everything from userdatamodel
and this file.

The `migrate` function in this file is called every init and can be used for
database migrations.
"""

from authlib.flask.oauth2.sqla import (
    OAuth2AuthorizationCodeMixin,
    OAuth2ClientMixin,
)
import flask
from sqlalchemy import (
    Integer, BigInteger, String, Column, Boolean, Text, MetaData, Table
)
from sqlalchemy.orm import relationship, backref
from sqlalchemy.schema import ForeignKey
from fence.jwt.token import CLIENT_ALLOWED_SCOPES
from userdatamodel import Base
from userdatamodel.models import (
    AccessPrivilege, Application, AuthorizationProvider, Bucket, Certificate,
    CloudProvider, ComputeAccess, GoogleProxyGroup, HMACKeyPair,
    HMACKeyPairArchive, IdentityProvider, Project, ProjectToBucket, Group,
    S3Credential, StorageAccess, User, Tag, UserToBucket, UserToGroup
)


class Client(Base, OAuth2ClientMixin):

    __tablename__ = 'client'

    client_id = Column(String(40), primary_key=True)
    # this is hashed secret
    client_secret = Column(String(60), unique=True, index=True, nullable=True)

    # human readable name
    name = Column(String(40), unique=True, nullable=False)

    # human readable description, not required
    description = Column(String(400))

    # required if you need to support client credential
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship(
        'User',
        backref=backref('clients', cascade='all, delete-orphan')
    )

    # this is for internal microservices to skip user grant
    auto_approve = Column(Boolean, default=False)

    # public or confidential
    is_confidential = Column(Boolean, default=True)

    _allowed_scopes = Column(Text, nullable=False, default='')

    _redirect_uris = Column(Text)
    _default_scopes = Column(Text)
    _scopes = ['compute', 'storage', 'user']

    def __init__(self, **kwargs):
        if 'allowed_scopes' in kwargs:
            allowed_scopes = kwargs.pop('allowed_scopes')
            if isinstance(allowed_scopes, list):
                kwargs['_allowed_scopes'] = ' '.join(allowed_scopes)
            else:
                kwargs['_allowed_scopes'] = allowed_scopes
        super(Client, self).__init__(**kwargs)

    @property
    def allowed_scopes(self):
        return self._allowed_scopes.split(' ')

    @property
    def client_type(self):
        """
        The client should be considered confidential either if it is actually
        marked confidential, *or* if the confidential setting was left empty.
        Only in the case where ``is_confidential`` is deliberately set to
        ``False`` should the client be considered public.
        """
        if self.is_confidential is False:
            return 'public'
        return 'confidential'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []

    @staticmethod
    def get_by_client_id(client_id):
        with flask.current_app.db.session as session:
            return (
                session
                .query(Client)
                .filter_by(client_id=client_id)
                .first()
            )

    def check_requested_scopes(self, scopes):
        return set(self.allowed_scopes).issuperset(scopes)

    def validate_scopes(self, scopes):
        scopes = scopes[0].split(',')
        return all(scope in self._scopes for scope in scopes)

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris


class AuthorizationCode(Base, OAuth2AuthorizationCodeMixin):

    __tablename__ = 'authorization_code'

    id = Column(Integer, primary_key=True)

    user_id = Column(
        Integer, ForeignKey('User.id', ondelete='CASCADE')
    )
    user = relationship(
        'User',
        backref=backref('authorization_codes', cascade='all, delete-orphan')
    )

    nonce = Column(String, nullable=True)

    _scope = Column(Text, default='')

    def __init__(self, **kwargs):
        if 'scope' in kwargs:
            scope = kwargs.pop('scope')
            if isinstance(scope, list):
                kwargs['_scope'] = ' '.join(scope)
            else:
                kwargs['_scope'] = scope
        super(AuthorizationCode, self).__init__(**kwargs)

    @property
    def scope(self):
        return self._scope.split(' ')


class UserRefreshToken(Base):
    __tablename__ = "user_refresh_token"

    jti = Column(String, primary_key=True)
    userid = Column(Integer)
    expires = Column(BigInteger)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()


class GoogleServiceAccount(Base):
    __tablename__ = "google_service_account"

    id = Column(Integer, primary_key=True)

    # The uniqueId google provides to resources is ONLY unique within
    # the given project, so we shouldn't rely on that for a primary key (in
    # case we're ever juggling mult. projects)
    google_unique_id = Column(
        String,
        unique=False,
        nullable=False
    )

    client_id = Column(
        String(40),
    )

    user_id = Column(
        Integer,
        ForeignKey(User.id),
        nullable=False
    )
    user = relationship(
        'User',
        backref=backref(
            'google_service_accounts', cascade='all, delete-orphan')
    )

    google_project_id = Column(
        String,
        unique=True,
        nullable=False
    )

    email = Column(
        String,
        unique=True,
        nullable=False
    )

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class UserGoogleAccount(Base):
    __tablename__ = "user_google_account"

    id = Column(Integer, primary_key=True)

    email = Column(
        String,
        unique=True,
        nullable=False
    )

    user_id = Column(
        Integer,
        ForeignKey(User.id),
        nullable=False
    )

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class UserGoogleAccountToProxyGroup(Base):
    __tablename__ = "user_google_account_to_proxy_group"

    user_google_account_id = Column(
        Integer,
        ForeignKey(UserGoogleAccount.id),
        nullable=False,
        primary_key=True
    )

    proxy_group_id = Column(
        String,
        ForeignKey(GoogleProxyGroup.id),
        nullable=False,
        primary_key=True
    )

    expires = Column(BigInteger)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class GoogleServiceAccountKey(Base):
    __tablename__ = "google_service_account_key"

    id = Column(Integer, primary_key=True)

    key_id = Column(String, nullable=False)

    service_account_id = Column(
        Integer,
        ForeignKey(GoogleServiceAccount.id),
        nullable=False
    )

    expires = Column(BigInteger)

    private_key = Column(String)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


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
        column=Column('email', String),
        driver=driver,
        metadata=md
    )

    drop_foreign_key_column_if_exist(
        table_name=GoogleProxyGroup.__tablename__,
        column_name='user_id',
        driver=driver,
        metadata=md
    )

    _add_google_project_id(driver, md)

    drop_unique_constraint_if_exist(
        table_name=GoogleServiceAccount.__tablename__,
        column_name='google_unique_id',
        driver=driver,
        metadata=md
    )


def add_foreign_key_column_if_not_exist(
        table_name, column_name, column_type, fk_table_name, fk_column_name, driver,
        metadata):
    column = Column(column_name, column_type)
    add_column_if_not_exist(
        table_name, column, driver, metadata)
    add_foreign_key_constraint_if_not_exist(
        table_name, column_name, fk_table_name, fk_column_name, driver,
        metadata)


def drop_foreign_key_column_if_exist(table_name, column_name, driver, metadata):
    drop_foreign_key_constraint_if_exist(
        table_name, column_name, driver, metadata)
    drop_column_if_exist(table_name, column_name, driver, metadata)


def add_column_if_not_exist(
        table_name, column, driver, metadata):
    column_name = column.compile(dialect=driver.engine.dialect)
    column_type = column.type.compile(driver.engine.dialect)

    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)
    if str(column_name) not in table.c:
        with driver.session as session:
            command = (
                "ALTER TABLE \"{}\" ADD COLUMN {} {}"
                .format(table_name, column_name, column_type)
            )
            if not column.nullable:
                command += " NOT NULL"
            command += ";"

            session.execute(command)
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
        foreign_keys = [
            fk.name for fk in getattr(table.c, column_name).foreign_keys
        ]
        if foreign_key_name in foreign_keys:
            with driver.session as session:
                session.execute(
                    "ALTER TABLE \"{}\" DROP CONSTRAINT {};"
                    .format(table_name, foreign_key_name)
                )
                session.commit()


def add_unique_constraint_if_not_exist(
        table_name, column_name, driver, metadata):
    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)
    index_name = "{}_{}_key".format(table_name, column_name)

    if column_name in table.c:
        indexes = [index.name for index in table.indexes]

        if index_name not in indexes:
            with driver.session as session:
                session.execute(
                    "ALTER TABLE \"{}\" ADD CONSTRAINT {} UNIQUE ({});"
                    .format(
                        table_name, index_name, column_name
                    )
                )
                session.commit()


def drop_unique_constraint_if_exist(
        table_name, column_name, driver, metadata):
    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)
    constraint_name = "{}_{}_key".format(table_name, column_name)

    if column_name in table.c:
        constraints = [
            constaint.name
            for constaint in getattr(table.c, column_name).constraints
        ]

        unique_index = None
        for index in table.indexes:
            if index.name == constraint_name:
                unique_index = index

        if constraint_name in constraints or unique_index:
            with driver.session as session:
                session.execute(
                    "ALTER TABLE \"{}\" DROP CONSTRAINT {};"
                    .format(table_name, constraint_name)
                )
                session.commit()


def drop_default_value(
        table_name, column_name, driver, metadata):
    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)

    if column_name in table.c:
        with driver.session as session:
            session.execute(
                "ALTER TABLE \"{}\" ALTER COLUMN \"{}\" DROP DEFAULT;"
                .format(table_name, column_name)
            )
            session.commit()


def add_not_null_constraint(
        table_name, column_name, driver, metadata):
    table = Table(
        table_name, metadata, autoload=True, autoload_with=driver.engine)

    if column_name in table.c:
        with driver.session as session:
            session.execute(
                "ALTER TABLE \"{}\" ALTER COLUMN \"{}\" SET NOT NULL;"
                .format(table_name, column_name)
            )
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
        column=Column('google_project_id', String),
        driver=driver,
        metadata=md)

    # make rows have unique values for new column
    with driver.session as session:
        rows_to_make_unique = (
            session.query(GoogleServiceAccount)
            .filter(GoogleServiceAccount.google_project_id.is_(None))
        )
        count = 0
        for row in rows_to_make_unique:
            row.google_project_id = count
            count += 1
    session.commit()

    # add unique constraint
    add_unique_constraint_if_not_exist(
        table_name=GoogleServiceAccount.__tablename__,
        column_name='google_project_id',
        driver=driver,
        metadata=md
    )

    # add not null constraint
    add_not_null_constraint(
        table_name=GoogleServiceAccount.__tablename__,
        column_name='google_project_id',
        driver=driver,
        metadata=md
    )
