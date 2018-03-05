"""
Models relating to auth but not users
"""
import flask

from authlib.flask.oauth2.sqla import OAuth2AuthorizationCodeMixin
from authlib.flask.oauth2.sqla import OAuth2ClientMixin
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.schema import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.orm import backref

from fence.models._base import Base
from fence.models.users import User


class IdentityProvider(Base):
    __tablename__ = 'identity_provider'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)

    google = "google"
    itrust = "itrust"
    fence = "fence"


class AuthorizationProvider(Base):
    __tablename__ = 'authorization_provider'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)


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
    user = relationship(
        'User',
        backref=backref('clients', cascade='all, delete-orphan')
    )

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
