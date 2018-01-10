"""
Models for `fence` service

The models here inherit from the `Base` in userdatamodel, so
when the fence app is initialized, the resulting db session includes
everything from userdatamodel and this file. There is also
a `migrate` function in this file that gets called every init.
"""

from flask import current_app as capp
from flask_sqlalchemy_session import current_session
from sqlalchemy import (
    Integer, String, Column, Boolean, Text, DateTime, MetaData, Table
)
from sqlalchemy.orm import relationship
from sqlalchemy.schema import ForeignKey

from userdatamodel import Base
from userdatamodel.models import *


class Client(Base):
    __tablename__ = "client"

    # human readable name, not required
    name = Column(String(40))

    # human readable description, not required
    description = Column(String(400))

    # required if you need to support client credential
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='clients')

    client_id = Column(String(40), primary_key=True)
    # this is hashed secret
    client_secret = Column(String(60), unique=True, index=True,
                           nullable=False)

    # this is for internal microservices to skip user grant
    auto_approve = Column(Boolean, default=False)

    # public or confidential
    is_confidential = Column(Boolean)

    _redirect_uris = Column(Text)
    _default_scopes = Column(Text)
    _scopes = ['compute', 'storage', 'user']
    allowed_grant_types = ["authorization_code", "refresh_token"]

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

    def validate_scopes(self, scopes):
        scopes = scopes[0].split(',')
        return all(scope in self._scopes for scope in scopes)


class Grant(Base):
    __tablename__ = "grant"

    id = Column(Integer, primary_key=True)

    user_id = Column(
        Integer, ForeignKey(User.id, ondelete='CASCADE')
    )
    user = relationship('User', backref="grants", lazy='subquery')

    client_id = Column(
        String(40), ForeignKey('client.client_id'),
        nullable=False,
    )
    client = relationship('Client', backref='grants')

    code = Column(String(255), index=True, nullable=False)

    redirect_uri = Column(String(255))
    expires = Column(DateTime)

    _scopes = Column(Text)

    def delete(self):
        current_session.delete(self)
        current_session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(Base):
    __tablename__ = "token"

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
        with capp.db.session as session:
            session.delete(self)
            session.commit()
            return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


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
        with capp.db.session as session:
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
        with capp.db.session as session:
            session.delete(self)
            session.commit()
            return self


def migrate(driver):
    if not driver.engine.dialect.supports_alter:
        print("This engine dialect doesn't support altering so we are not migrating even if necessary!")
        return

    md = MetaData()
    table = Table(Token.__tablename__, md, autoload=True, autoload_with=driver.engine)

    if str(table.c.access_token.type) != 'VARCHAR':
        print("Altering table %s access_token to String" % (Token.__tablename__))
        with driver.session as session:
            session.execute("ALTER TABLE %s ALTER COLUMN access_token TYPE VARCHAR;" % (Token.__tablename__))

    if str(table.c.refresh_token.type) != 'VARCHAR':
        print("Altering table %s refresh_token to String" % (Token.__tablename__))
        with driver.session as session:
            session.execute("ALTER TABLE %s ALTER COLUMN refresh_token TYPE VARCHAR;" % (Token.__tablename__))
