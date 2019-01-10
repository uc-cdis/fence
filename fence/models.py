"""
Define sqlalchemy models.

The models here inherit from the `Base` in userdatamodel, so when the fence app
is initialized, the resulting db session includes everything from userdatamodel
and this file.

The `migrate` function in this file is called every init and can be used for
database migrations.
"""

from enum import Enum

from authlib.flask.oauth2.sqla import OAuth2AuthorizationCodeMixin, OAuth2ClientMixin
import bcrypt
import flask
from sqlalchemy import (
    Integer,
    BigInteger,
    String,
    Column,
    Boolean,
    Text,
    MetaData,
    Table,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import relationship, backref
from sqlalchemy import func
from sqlalchemy.schema import ForeignKey
from fence.jwt.token import CLIENT_ALLOWED_SCOPES
from userdatamodel import Base
from userdatamodel.models import (
    AccessPrivilege,
    Application,
    AuthorizationProvider,
    Bucket,
    Certificate,
    CloudProvider,
    ComputeAccess,
    GoogleProxyGroup,
    Group,
    HMACKeyPair,
    HMACKeyPairArchive,
    IdentityProvider,
    Policy,
    Project,
    ProjectToBucket,
    S3Credential,
    StorageAccess,
    Tag,
    User,
    UserToBucket,
    UserToGroup,
    users_to_policies,
)


def query_for_user(session, username):
    return (
        session.query(User)
        .filter(func.lower(User.username) == username.lower())
        .first()
    )


class ClientAuthType(Enum):
    """
    List the possible types of OAuth client authentication, which are

    - None (no authentication).
    - Basic (using basic HTTP authorization header to include the client ID & secret).
    - POST (the client ID & secret are included in the body of a POST request).

    These all have a corresponding string which identifies them to authlib.
    """

    none = "none"
    basic = "client_secret_basic"
    post = "client_secret_post"


class GrantType(Enum):
    """
    Enumerate the allowed grant types for the OAuth2 flow.
    """

    code = "authorization_code"
    refresh = "refresh_token"
    implicit = "implicit"
    client_credentials = "client_credentials"


class Client(Base, OAuth2ClientMixin):

    __tablename__ = "client"

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
        "User", backref=backref("clients", cascade="all, delete-orphan")
    )

    # this is for internal microservices to skip user grant
    auto_approve = Column(Boolean, default=False)

    # public or confidential
    is_confidential = Column(Boolean, default=True)

    # NOTE: DEPRECATED
    # Client now uses `redirect_uri` column, from authlib client model
    _redirect_uris = Column(Text)

    _allowed_scopes = Column(Text, nullable=False, default="")

    _default_scopes = Column(Text)
    _scopes = ["compute", "storage", "user"]

    # note that authlib adds a response_type column which is not used here

    def __init__(self, client_id, **kwargs):
        """
        NOTE that for authlib, the client must have an attribute ``redirect_uri`` which
        is a newline-delimited list of valid redirect URIs.
        """
        if "allowed_scopes" in kwargs:
            allowed_scopes = kwargs.pop("allowed_scopes")
            if isinstance(allowed_scopes, list):
                kwargs["_allowed_scopes"] = " ".join(allowed_scopes)
            else:
                kwargs["_allowed_scopes"] = allowed_scopes
        if "redirect_uris" in kwargs:
            redirect_uris = kwargs.pop("redirect_uris")
            if isinstance(redirect_uris, list):
                kwargs["redirect_uri"] = "\n".join(redirect_uris)
            else:
                kwargs["redirect_uri"] = redirect_uris
        # default grant types to allow for auth code flow and resfreshing
        grant_types = kwargs.pop("grant_types", None) or [
            GrantType.code.value,
            GrantType.refresh.value,
        ]
        if isinstance(grant_types, list):
            kwargs["grant_type"] = "\n".join(grant_types)
        else:
            # assume it's already in correct format
            kwargs["grant_type"] = grant_types

        super(Client, self).__init__(client_id=client_id, **kwargs)

    @property
    def allowed_scopes(self):
        return self._allowed_scopes.split(" ")

    @property
    def client_type(self):
        """
        The client should be considered confidential either if it is actually
        marked confidential, *or* if the confidential setting was left empty.
        Only in the case where ``is_confidential`` is deliberately set to
        ``False`` should the client be considered public.
        """
        if self.is_confidential is False:
            return "public"
        return "confidential"

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
            return session.query(Client).filter_by(client_id=client_id).first()

    def check_client_type(self, client_type):
        return (client_type == "confidential" and self.is_confidential) or (
            client_type == "public" and not self.is_confidential
        )

    def check_client_secret(self, client_secret):
        check_hash = bcrypt.hashpw(
            client_secret.encode("utf-8"), self.client_secret.encode("utf-8")
        )
        return check_hash == self.client_secret

    def check_requested_scopes(self, scopes):
        if "openid" not in scopes:
            return False
        return set(self.allowed_scopes).issuperset(scopes)

    def check_token_endpoint_auth_method(self, method):
        """
        Only basic auth is supported. If anything else gets added, change this
        """
        protected_types = [ClientAuthType.basic.value, ClientAuthType.post.value]
        return (self.is_confidential and method in protected_types) or (
            not self.is_confidential and method == ClientAuthType.none.value
        )

    def validate_scopes(self, scopes):
        scopes = scopes[0].split(",")
        return all(scope in self._scopes for scope in scopes)

    def check_response_type(self, response_type):
        allowed_response_types = []
        if "authorization_code" in self.grant_types:
            allowed_response_types.append("code")
        if "implicit" in self.grant_types:
            allowed_response_types.append("id_token")
            allowed_response_types.append("id_token token")
        return response_type in allowed_response_types


class AuthorizationCode(Base, OAuth2AuthorizationCodeMixin):

    __tablename__ = "authorization_code"

    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("User.id", ondelete="CASCADE"))
    user = relationship(
        "User", backref=backref("authorization_codes", cascade="all, delete-orphan")
    )

    nonce = Column(String, nullable=True)

    _scope = Column(Text, default="")

    def __init__(self, **kwargs):
        if "scope" in kwargs:
            scope = kwargs.pop("scope")
            if isinstance(scope, list):
                kwargs["_scope"] = " ".join(scope)
            else:
                kwargs["_scope"] = scope
        super(AuthorizationCode, self).__init__(**kwargs)

    @property
    def scope(self):
        return self._scope.split(" ")


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
    google_unique_id = Column(String, unique=False, nullable=False)

    client_id = Column(String(40))

    user_id = Column(Integer, ForeignKey(User.id), nullable=False)
    user = relationship(
        "User", backref=backref("google_service_accounts", cascade="all, delete-orphan")
    )

    google_project_id = Column(String, nullable=False)

    email = Column(String, unique=True, nullable=False)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class UserGoogleAccount(Base):
    __tablename__ = "user_google_account"

    id = Column(Integer, primary_key=True)

    email = Column(String, unique=True, nullable=False)

    user_id = Column(Integer, ForeignKey(User.id), nullable=False)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class UserGoogleAccountToProxyGroup(Base):
    __tablename__ = "user_google_account_to_proxy_group"

    user_google_account_id = Column(
        Integer, ForeignKey(UserGoogleAccount.id), nullable=False, primary_key=True
    )

    proxy_group_id = Column(
        String, ForeignKey(GoogleProxyGroup.id), nullable=False, primary_key=True
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
        Integer, ForeignKey(GoogleServiceAccount.id), nullable=False
    )

    expires = Column(BigInteger)

    private_key = Column(String)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class GoogleBucketAccessGroup(Base):
    __tablename__ = "google_bucket_access_group"
    id = Column(Integer, primary_key=True)

    bucket_id = Column(Integer, ForeignKey(Bucket.id), nullable=False)
    bucket = relationship(
        "Bucket",
        backref=backref("google_bucket_access_groups", cascade="all, delete-orphan"),
    )

    email = Column(String, nullable=False)

    # specify what kind of storage access this group has e.g. ['read-storage']
    privileges = Column(ARRAY(String))

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class GoogleProxyGroupToGoogleBucketAccessGroup(Base):
    __tablename__ = "google_proxy_group_to_google_bucket_access_group"
    id = Column(Integer, primary_key=True)

    proxy_group_id = Column(String, ForeignKey(GoogleProxyGroup.id), nullable=False)
    proxy_group = relationship(
        "GoogleProxyGroup",
        backref=backref("bucket_access_groups", cascade="all, delete-orphan"),
    )

    access_group_id = Column(
        Integer, ForeignKey(GoogleBucketAccessGroup.id), nullable=False
    )
    access_group = relationship(
        "GoogleBucketAccessGroup",
        backref=backref("proxy_groups_with_access", cascade="all, delete-orphan"),
    )


class UserServiceAccount(Base):
    __tablename__ = "user_service_account"
    id = Column(Integer, primary_key=True)

    # The uniqueId google provides to resources is ONLY unique within
    # the given project, so we shouldn't rely on that for a primary key (in
    # case we're ever juggling mult. projects)
    google_unique_id = Column(String, nullable=False)

    email = Column(String, nullable=False)

    google_project_id = Column(String, nullable=False)


class ServiceAccountAccessPrivilege(Base):
    __tablename__ = "service_account_access_privilege"

    id = Column(Integer, primary_key=True)

    project_id = Column(Integer, ForeignKey(Project.id), nullable=False)

    project = relationship(
        "Project", backref=backref("sa_access_privileges", cascade="all, delete-orphan")
    )

    service_account_id = Column(
        Integer, ForeignKey(UserServiceAccount.id), nullable=False
    )

    service_account = relationship(
        "UserServiceAccount",
        backref=backref("access_privileges", cascade="all, delete-orphan"),
    )


class ServiceAccountToGoogleBucketAccessGroup(Base):
    __tablename__ = "service_account_to_google_bucket_access_group"
    id = Column(Integer, primary_key=True)

    service_account_id = Column(
        Integer, ForeignKey(UserServiceAccount.id), nullable=False
    )

    service_account = relationship(
        "UserServiceAccount",
        backref=backref("to_access_groups", cascade="all, delete-orphan"),
    )

    expires = Column(BigInteger)

    access_group_id = Column(
        Integer, ForeignKey(GoogleBucketAccessGroup.id), nullable=False
    )

    access_group = relationship(
        "GoogleBucketAccessGroup",
        backref=backref("to_access_groups", cascade="all, delete-orphan"),
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

    # oidc migration

    table = Table(Client.__tablename__, md, autoload=True, autoload_with=driver.engine)
    if not any([index.name == "ix_name" for index in table.indexes]):
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
                    client._allowed_scopes = " ".join(CLIENT_ALLOWED_SCOPES)
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
                    "FOREIGN KEY({}) REFERENCES {} ({});".format(
                        table_name,
                        foreign_key_name,
                        column_name,
                        fk_table_name,
                        fk_column_name,
                    )
                )
                session.commit()


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
    map(add_client_col, CLIENT_COLUMNS_TO_ADD)
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
    map(add_code_col, CODE_COLUMNS_TO_ADD)
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
