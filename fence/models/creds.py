"""
Models relating to credentials
"""
import json
import flask
import datetime

from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Column
from sqlalchemy import Boolean
from sqlalchemy import BigInteger
from sqlalchemy import DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.schema import ForeignKey

from fence.models._base import Base
from fence.models.users import User


class UserRefreshToken(Base):
    __tablename__ = "user_refresh_token"

    jti = Column(String, primary_key=True)
    userid = Column(Integer)
    expires = Column(BigInteger)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()


class S3Credential(Base):
    __tablename__ = 's3credential'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='s3credentials')

    access_key = Column(String)

    timestamp = Column(
        DateTime, nullable=False, default=datetime.datetime.utcnow)
    expire = Column(Integer)


class HMACKeyPair(Base):
    __tablename__ = 'hmac_keypair'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='hmac_keypairs')

    access_key = Column(String)
    # AES-128 encrypted
    secret_key = Column(String)

    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    expire = Column(Integer)
    active = Column(Boolean, default=True)

    @property
    def expiration_time(self):
        return self.timestamp + datetime.timedelta(seconds=self.expire)

    def check_and_archive(self, session):
        if self.expiration_time < datetime.datetime.utcnow():
            self.archive_keypair(session)
            return True
        return False

    def archive_keypair(self, session):
        archive = HMACKeyPairArchive(
            user_id=self.user_id,
            access_key=self.access_key,
            secret_key=self.secret_key,
            timestamp=self.timestamp,
            expire=self.expire)
        session.add(archive)
        session.delete(self)
        session.commit()

    def __str__(self):
        str_out = {
            'id': self.id,
            'user_id': self.user_id,
            'access_key': self.access_key,
            'secret_key': self.secret_key,
            'timestamp': self.timestamp,
            'expire': self.expire,
            'active': self.active
        }
        return json.dumps(str_out)

    def __repr__(self):
        return self.__str__()


class HMACKeyPairArchive(Base):
    '''
    Archive table to store expired or deleted keypair
    '''
    __tablename__ = 'hmac_keypair_archive'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='archive_keypairs')

    access_key = Column(String)
    # AES-128 encrypted
    secret_key = Column(String)

    timestamp = Column(DateTime, nullable=False)
    expire = Column(Integer)
