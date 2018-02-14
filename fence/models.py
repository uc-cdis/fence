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
from sqlalchemy.orm import relationship
from sqlalchemy.schema import ForeignKey
from fence.jwt.token import CLIENT_ALLOWED_SCOPES
from userdatamodel import Base
from userdatamodel.models import (
    AccessPrivilege, Application, AuthorizationProvider, Bucket, Certificate,
    CloudProvider, ComputeAccess, HMACKeyPair, HMACKeyPairArchive,
    IdentityProvider, Project, ProjectToBucket, Group, S3Credential,
    StorageAccess, User, UserToBucket
)


class Client(Base, OAuth2ClientMixin):

    __tablename__ = 'client'

    client_id = Column(String(40), primary_key=True)
    # this is hashed secret
    client_secret = Column(String(60), unique=True, index=True, nullable=False)

    # human readable name
    name = Column(String(40), unique=True, nullable=False)

    # human readable description, not required
    description = Column(String(400))

    # required if you need to support client credential
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='clients')

    # this is for internal microservices to skip user grant
    auto_approve = Column(Boolean, default=False)

    # public or confidential
    is_confidential = Column(Boolean)

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
        if self.is_confidential:
            return 'confidential'
        return 'public'

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
    user = relationship('User')

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
        unique=True,
        nullable=False
    )

    client_id = Column(
        String(40),
        ForeignKey('client.client_id')
    )
    client = relationship('Client')

    user_id = Column(
        Integer,
        ForeignKey(User.id),
        nullable=False
    )
    user = relationship('User')

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


class GoogleProxyGroup(Base):
    __tablename__ = "google_proxy_group"

    id = Column(String(90), primary_key=True)

    user_id = Column(
        Integer,
        ForeignKey(User.id),
        nullable=False,
        unique=True
    )
    user = relationship('User')

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
