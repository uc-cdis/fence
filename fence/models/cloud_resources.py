"""
Models relating to cloud resources
"""
import flask

from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Column
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.orm import relationship
from sqlalchemy.orm import backref
from sqlalchemy.schema import ForeignKey

from fence.models._base import Base
from fence.models.users import User


class CloudProvider(Base):
    __tablename__ = 'cloud_provider'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    endpoint = Column(String, unique=True)
    backend = Column(String)
    description = Column(String)
    # type of service, can be compute, storage, or general
    service = Column(String)


class Bucket(Base):
    __tablename__ = 'bucket'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    provider_id = Column(Integer, ForeignKey('cloud_provider.id'))
    provider = relationship('CloudProvider', backref='buckets')
    users = association_proxy(
        'user_to_buckets',
        'user')


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
    client = relationship(
        'Client',
        backref=backref('google_service_accounts', cascade='all, delete-orphan')
    )

    user_id = Column(
        Integer,
        ForeignKey(User.id),
        nullable=False
    )
    user = relationship(
        'User',
        backref=backref('google_service_accounts', cascade='all, delete-orphan')
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


class GoogleProxyGroup(Base):
    __tablename__ = "google_proxy_group"

    id = Column(String(90), primary_key=True)

    user_id = Column(
        Integer,
        ForeignKey(User.id),
        nullable=False,
        unique=True
    )
    user = relationship(
        'User',
        backref=backref('google_proxy_groups', cascade='all, delete-orphan')
    )

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self
