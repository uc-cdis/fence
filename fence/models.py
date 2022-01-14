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
    DateTime,
    String,
    Column,
    Boolean,
    Text,
    MetaData,
    Table,
    text,
    event,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func
from sqlalchemy import exc as sa_exc
from sqlalchemy import func
from sqlalchemy.schema import ForeignKey
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
    Project,
    ProjectToBucket,
    S3Credential,
    StorageAccess,
    Tag,
    User,
    UserToBucket,
    UserToGroup,
)
import warnings

from fence import logger
from fence.config import config


def query_for_user(session, username):
    return (
        session.query(User)
        .filter(func.lower(User.username) == username.lower())
        .first()
    )


def create_user(session, logger, username, email=None, idp_name=None):
    """
    Create a new user in the database.

    Args:
        session (sqlalchemy.orm.session.Session): database session
        logger (logging.Logger): logger
        username (str): username to save for the created user
        email (str): email to save for the created user
        idp_name (str): name of identity provider to link

    Return:
        userdatamodel.user.User: the created user
    """
    logger.info(f'Creating a new Fence user with username "{username}"')

    user = User(username=username)
    if email:
        user.email = email
    if idp_name:
        idp = (
            session.query(IdentityProvider)
            .filter(IdentityProvider.name == idp_name)
            .first()
        )
        if not idp:
            idp = IdentityProvider(name=idp_name)
        user.identity_provider = idp

    session.add(user)
    session.commit()
    return user


def get_project_to_authz_mapping(session):
    """
    Get the mappings for Project.auth_id to authorization resource (Project.authz)
    from the database if a mapping exists. e.g. will only return if Project.authz is
    populated.

    Args:
        session (sqlalchemy.orm.session.Session): database session

    Returns:
        dict{str:str}: Mapping from Project.auth_id to Project.authz
    """
    output = {}

    query_results = session.query(Project.auth_id, Project.authz)
    if query_results:
        output = {item.auth_id: item.authz for item in query_results if item.authz}

    return output


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
    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"))
    user = relationship(
        "User",
        backref=backref("clients", cascade="all, delete-orphan", passive_deletes=True),
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
        ).decode("utf-8")
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
        "User",
        backref=backref(
            "authorization_codes", cascade="all, delete-orphan", passive_deletes=True
        ),
    )

    nonce = Column(String, nullable=True)

    refresh_token_expires_in = Column(Integer, nullable=True)

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

    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False)
    user = relationship(
        "User",
        backref=backref(
            "google_service_accounts",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
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

    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False)
    user = relationship(
        "User",
        backref=backref(
            "user_google_accounts", cascade="all, delete-orphan", passive_deletes=True
        ),
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
        ForeignKey(UserGoogleAccount.id, ondelete="CASCADE"),
        nullable=False,
        primary_key=True,
    )
    user_google_account = relationship(
        "UserGoogleAccount",
        backref=backref(
            "user_google_account_to_proxy_group",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    proxy_group_id = Column(
        String,
        ForeignKey(GoogleProxyGroup.id, ondelete="CASCADE"),
        nullable=False,
        primary_key=True,
    )
    google_proxy_group = relationship(
        "GoogleProxyGroup",
        backref=backref(
            "user_google_account_to_proxy_group",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
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
        Integer, ForeignKey(GoogleServiceAccount.id, ondelete="CASCADE"), nullable=False
    )
    google_service_account = relationship(
        "GoogleServiceAccount",
        backref=backref(
            "google_service_account_keys",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
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

    bucket_id = Column(
        Integer, ForeignKey(Bucket.id, ondelete="CASCADE"), nullable=False
    )
    bucket = relationship(
        "Bucket",
        backref=backref(
            "google_bucket_access_groups",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
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

    proxy_group_id = Column(
        String, ForeignKey(GoogleProxyGroup.id, ondelete="CASCADE"), nullable=False
    )
    proxy_group = relationship(
        "GoogleProxyGroup",
        backref=backref(
            "google_proxy_group_to_google_bucket_access_group",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    access_group_id = Column(
        Integer,
        ForeignKey(GoogleBucketAccessGroup.id, ondelete="CASCADE"),
        nullable=False,
    )
    access_group = relationship(
        "GoogleBucketAccessGroup",
        backref=backref(
            "google_proxy_group_to_google_bucket_access_group",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    expires = Column(BigInteger)


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

    project_id = Column(
        Integer, ForeignKey(Project.id, ondelete="CASCADE"), nullable=False
    )
    project = relationship(
        "Project",
        backref=backref(
            "sa_access_privileges", cascade="all, delete-orphan", passive_deletes=True
        ),
    )

    service_account_id = Column(
        Integer, ForeignKey(UserServiceAccount.id, ondelete="CASCADE"), nullable=False
    )
    service_account = relationship(
        "UserServiceAccount",
        backref=backref(
            "access_privileges", cascade="all, delete-orphan", passive_deletes=True
        ),
    )


class ServiceAccountToGoogleBucketAccessGroup(Base):
    __tablename__ = "service_account_to_google_bucket_access_group"
    id = Column(Integer, primary_key=True)

    service_account_id = Column(
        Integer, ForeignKey(UserServiceAccount.id, ondelete="CASCADE"), nullable=False
    )
    service_account = relationship(
        "UserServiceAccount",
        backref=backref(
            "to_access_groups", cascade="all, delete-orphan", passive_deletes=True
        ),
    )

    expires = Column(BigInteger)

    access_group_id = Column(
        Integer,
        ForeignKey(GoogleBucketAccessGroup.id, ondelete="CASCADE"),
        nullable=False,
    )

    access_group = relationship(
        "GoogleBucketAccessGroup",
        backref=backref(
            "to_access_groups", cascade="all, delete-orphan", passive_deletes=True
        ),
    )


class AssumeRoleCacheAWS(Base):
    __tablename__ = "assume_role_cache"

    arn = Column(String(), primary_key=True)
    expires_at = Column(Integer())
    aws_access_key_id = Column(String())
    aws_secret_access_key = Column(String())
    aws_session_token = Column(String())


class AssumeRoleCacheGCP(Base):
    __tablename__ = "gcp_assume_role_cache"

    gcp_proxy_group_id = Column(String(), primary_key=True)
    expires_at = Column(Integer())
    gcp_private_key = Column(String())
    gcp_key_db_entry = Column(String())


class GA4GHVisaV1(Base):

    __tablename__ = "ga4gh_visa_v1"

    # As Fence will consume visas from many visa issuers, will not use jti as pkey
    id = Column(BigInteger, primary_key=True)

    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False)
    user = relationship(
        "User",
        backref=backref(
            "ga4gh_visas_v1", cascade="all, delete-orphan", passive_deletes=True
        ),
    )
    ga4gh_visa = Column(Text, nullable=False)  # In encoded form
    source = Column(String, nullable=False)
    type = Column(String, nullable=False)
    asserted = Column(BigInteger, nullable=False)
    expires = Column(BigInteger, nullable=False)


class UpstreamRefreshToken(Base):
    # General table to store any refresh_token sent from any oidc client

    __tablename__ = "upstream_refresh_token"

    id = Column(BigInteger, primary_key=True)

    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False)
    user = relationship(
        "User",
        backref=backref(
            "upstream_refresh_tokens",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )
    refresh_token = Column(Text, nullable=False)
    expires = Column(BigInteger, nullable=False)


class IssSubPairToUser(Base):
    # issuer & sub pair mapping to Gen3 User sub

    __tablename__ = "iss_sub_pair_to_user"

    iss = Column(String(), primary_key=True)
    sub = Column(String(), primary_key=True)

    fk_to_User = Column(
        Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False
    )  #  foreign key for User table
    user = relationship(
        "User",
        backref=backref(
            "iss_sub_pairs",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    # dump whatever idp provides in here
    extra_info = Column(JSONB(), server_default=text("'{}'"))

    def _get_issuer_to_idp():
        possibly_matching_idps = [IdentityProvider.ras]
        issuer_to_idp = {}

        oidc = config.get("OPENID_CONNECT", {})
        for idp in possibly_matching_idps:
            discovery_url = oidc.get(idp, {}).get("discovery_url")
            if discovery_url:
                for allowed_issuer in config["GA4GH_VISA_ISSUER_ALLOWLIST"]:
                    if discovery_url.startswith(allowed_issuer):
                        issuer_to_idp[allowed_issuer] = idp
                        break

        return issuer_to_idp

    ISSUER_TO_IDP = _get_issuer_to_idp()

    # no longer need function since results stored in var
    del _get_issuer_to_idp


@event.listens_for(IssSubPairToUser.__table__, "after_create")
def populate_iss_sub_pair_to_user_table(target, connection, **kw):
    """
    Populate iss_sub_pair_to_user table using User table's id_from_idp
    column.
    """
    for issuer, idp_name in IssSubPairToUser.ISSUER_TO_IDP.items():
        logger.info(
            'Attempting to populate iss_sub_pair_to_user table for users with "{}" idp and "{}" issuer'.format(
                idp_name, issuer
            )
        )
        transaction = connection.begin()
        try:
            connection.execute(
                text(
                    """
                    WITH identity_provider_id AS (SELECT id FROM identity_provider WHERE name=:idp_name)
                    INSERT INTO iss_sub_pair_to_user (iss, sub, "fk_to_User", extra_info)
                    SELECT :iss, id_from_idp, id, additional_info
                    FROM "User"
                    WHERE idp_id IN (SELECT * FROM identity_provider_id) AND id_from_idp IS NOT NULL;
                    """
                ),
                idp_name=idp_name,
                iss=issuer,
            )
        except Exception as e:
            transaction.rollback()
            logger.warning(
                "Could not populate iss_sub_pair_to_user table: {}".format(e)
            )
        else:
            transaction.commit()
            logger.info("Population was successful")


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
