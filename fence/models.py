import flask
from flask_postgres_session import user_session_model
from sqlalchemy import (
    Integer, String, Column, Boolean, Text, DateTime, MetaData, Table
)
from sqlalchemy.orm import relationship
from sqlalchemy.schema import ForeignKey
from userdatamodel import Base
from userdatamodel.models import *


UserSession = user_session_model('fence_user_session', Base=Base)


class Client(Base):

    __tablename__ = 'client'

    client_id = Column(String(40), primary_key=True)
    # this is hashed secret
    client_secret = Column(String(60), unique=True, index=True, nullable=False)

    # human readable name, not required
    name = Column(String(40))

    # human readable description, not required
    description = Column(String(400))

    # required if you need to support client credential
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='clients')

    # this is for internal microservices to skip user grant
    auto_approve = Column(Boolean, default=False)

    # public or confidential
    is_confidential = Column(Boolean)

    _redirect_uris = Column(Text)
    _default_scopes = Column(Text)
    _scopes = ['compute', 'storage', 'user']

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
        return all(scope in self._scopes for scope in scopes)

    def validate_scopes(self, scopes):
        scopes = scopes[0].split(',')
        return all(scope in self._scopes for scope in scopes)


class Token(Base):

    __tablename__ = 'token'

    id = Column(Integer, primary_key=True)

    client_id = Column(
        String(40),
        ForeignKey('client.client_id'),
        nullable=False,
    )
    client = relationship('Client')

    user_id = Column(
        Integer, ForeignKey(User.id)
    )
    user = relationship('User')

    # currently only bearer is supported
    token_type = Column(String(40))

    access_token = Column(String, unique=True)
    refresh_token = Column(String, unique=True)
    expires = Column(DateTime)
    _scopes = Column(Text)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class AuthorizationCode(Base):

    __tablename__ = 'authorization_code'

    code = Column(Integer, primary_key=True)

    user_id = Column(
        Integer, ForeignKey('User.id', ondelete='CASCADE')
    )
    user = relationship('User')


def migrate(driver):
    if not driver.engine.dialect.supports_alter:
        print(
            "This engine dialect doesn't support altering so we are not"
            " migrating even if necessary!"
        )
        return

    md = MetaData()
    table = Table(
        Token.__tablename__,
        md,
        autoload=True,
        autoload_with=driver.engine,
    )

    if str(table.c.access_token.type) != 'VARCHAR':
        print(
            'Altering table %s access_token to String'
            % (Token.__tablename__)
        )
        with driver.session as session:
            session.execute(
                'ALTER TABLE %s ALTER COLUMN access_token TYPE VARCHAR;'
                % (Token.__tablename__)
            )

    if str(table.c.refresh_token.type) != 'VARCHAR':
        print(
            'Altering table %s refresh_token to String'
            % (Token.__tablename__)
        )
        with driver.session as session:
            session.execute(
                'ALTER TABLE %s ALTER COLUMN refresh_token TYPE VARCHAR;'
                % (Token.__tablename__)
            )

    table = Table(
        Client.__tablename__,
        md,
        autoload=True,
        autoload_with=driver.engine,
    )

    with driver.session as session:
        cols_to_add = [
        ]
        for col, col_type in cols_to_add:
            session.execute(
                'ALTER TABLE {} ADD COLUMN {} {}'
                .format(Client.__tablename__, col, col_type)
            )
