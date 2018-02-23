"""
Define sqlalchemy models.

The models here inherit from the `Base` in userdatamodel, so when the fence app
is initialized, the resulting db session includes everything from userdatamodel
and this file.

The `migrate` function in this file is called every init and can be used for
database migrations.
"""
import json
import flask
import datetime

from authlib.flask.oauth2.sqla import (
    OAuth2AuthorizationCodeMixin,
    OAuth2ClientMixin,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Integer, String, Column, Table, Boolean, BigInteger, MetaData, DateTime, Text, text)
from sqlalchemy import UniqueConstraint, Index, CheckConstraint
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship, backref
from sqlalchemy.schema import ForeignKey
from sqlalchemy.types import LargeBinary
from sqlalchemy.orm.collections import MappedCollection, collection

from fence.jwt.token import CLIENT_ALLOWED_SCOPES

IDENTITY_PROVIDERS = ['google', 'itrust']  # TODO get these from config?
Base = declarative_base()
user_group = Table(
    'user_group', Base.metadata,
    Column('user_id', Integer, ForeignKey('User.id')),
    Column('group_id', Integer, ForeignKey('research_group.id'))
)


class PrivilegeDict(MappedCollection):
    '''
    PrivilegeDict is used to populate the list of all privileges
    a user by the project_id.
    User can have privilege access to a project via multiple groups,
    the list of privileges of a user in a project should be a union
    of all groups that user belongs.
    For example: user_1, group_1, project_1: [read-storage]
                 user_1, group_2, project_1: [write-storage]
                 --> user_1, project_1: [read-storage, write-storage]
    '''
    def __init__(self):
        MappedCollection.__init__(self, keyfunc=lambda node: node.project_id)

    @collection.internally_instrumented
    def __setitem__(self, key, value, _sa_initiator=None):
        # do something with key, value
        if self.has_key(key):
            for item in value.privilege:
                if item not in self[key].privilege:
                    self[key].privilege.append(item)
        else:
            super(PrivilegeDict, self).__setitem__(key, value, _sa_initiator)


class User(Base):
    __tablename__ = 'User'

    id = Column(Integer, primary_key=True)
    username = Column(String(40), unique=True)

    # id from identifier, which is not guarenteed to be unique
    # across all identifiers.
    # For most of the cases, it will be same as username
    id_from_idp = Column(String)
    email = Column(String)

    idp_id = Column(Integer, ForeignKey('identity_provider.id'))
    identity_provider = relationship('IdentityProvider', backref='users')

    department_id = Column(Integer, ForeignKey('department.id'))
    department = relationship('Department', backref='users')

    research_groups = relationship(
        'ResearchGroup', secondary=user_group, backref='users')

    group_privileges = relationship(
        'AccessPrivilege', primaryjoin='user_group.c.user_id==User.id',
        secondary='join(AccessPrivilege, ResearchGroup, AccessPrivilege.group_id==ResearchGroup.id).'
                  'join(user_group, ResearchGroup.id == user_group.c.group_id)',
        collection_class=PrivilegeDict
    )
    group_accesses = association_proxy('group_privileges',
                                       'privilege',
                                       creator=lambda k, v: AccessPrivilege(privilege=v, pj=k))

    active = Column(Boolean)
    is_admin = Column(Boolean, default=False)

    projects = association_proxy(
        'accesses_privilege',
        'project')

    project_access = association_proxy(
        'accesses_privilege',
        'privilege',
        creator=lambda k, v: AccessPrivilege(privilege=v, pj=k)
        )

    buckets = association_proxy(
        'user_to_buckets',
        'bucket')

    application = relationship('Application', backref='user', uselist=False)

    def __str__(self):
        str_out = {
            'id': self.id,
            'username': self.username,
            'id_from_idp': self.id_from_idp,
            'idp_id': self.idp_id,
            'department_id': self.department_id,
            'active': self.active,
            'is_admin': self.is_admin,
            'group_privileges': str(self.group_privileges),
            'group_accesses': str(self.group_accesses),
            'projects': str(self.projects),
            'project_access': str(self.project_access)
        }
        return json.dumps(str_out)

    def __repr__(self):
        return self.__str__()


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


class AccessPrivilege(Base):
    '''
    A group/user's privileges on a project.
    The group and user columns should be mutually exclusive
    '''
    __tablename__ = 'access_privilege'
    __table_args__ = (
        UniqueConstraint('user_id', 'group_id', 'project_id', name='uniq_ap'),
        CheckConstraint(
            'user_id is NULL or group_id is NULL',
            name='check_access_subject'),
        Index('unique_group_project_id', 'group_id', 'project_id', unique=True,
              postgresql_where=text('user_id is NULL')),
        Index('unique_user_project_id', 'user_id', 'project_id', unique=True,
              postgresql_where=text('group_id is NULL')),
        Index('unique_user_group_id', 'user_id', 'group_id', unique=True,
              postgresql_where=text('project_id is NULL'))
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship(
        User,
        backref=backref('accesses_privilege',
                        collection_class=attribute_mapped_collection('pj'))
    )

    group_id = Column(Integer, ForeignKey('research_group.id'))
    research_group = relationship('ResearchGroup', backref='accesses_privilege')

    project_id = Column(Integer, ForeignKey('project.id'))
    project = relationship('Project', backref='accesses_privilege')
    pj = association_proxy('project', 'auth_id')

    privilege = Column(ARRAY(String))
    provider_id = Column(Integer, ForeignKey('authorization_provider.id'))
    auth_provider = relationship('AuthorizationProvider', backref='acls')

    def __str__(self):
        str_out = {
            'id': self.id,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'group_id': self.group_id,
            'privilege': self.privilege,
            'provider_id': self.provider_id
        }
        return json.dumps(str_out)

    def __repr__(self):
        return self.__str__()


class UserToBucket(Base):
    __tablename__ = 'user_to_bucket'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship(User, backref='user_to_buckets')

    bucket_id = Column(Integer, ForeignKey('bucket.id'))

    bucket = relationship('Bucket', backref='user_to_buckets')
    privilege = Column(ARRAY(String))


class ResearchGroup(Base):
    __tablename__ = 'research_group'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)

    lead_id = Column(Integer, ForeignKey(User.id))
    lead = relationship('User', backref='lead_group')


class IdentityProvider(Base):
    __tablename__ = 'identity_provider'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)

    google = 'google'
    itrust = 'itrust'


class AuthorizationProvider(Base):
    __tablename__ = 'authorization_provider'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)


class Bucket(Base):
    __tablename__ = 'bucket'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    provider_id = Column(Integer, ForeignKey('cloud_provider.id'))
    provider = relationship('CloudProvider', backref='buckets')
    users = association_proxy(
        'user_to_buckets',
        'user')


class CloudProvider(Base):
    __tablename__ = 'cloud_provider'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    endpoint = Column(String, unique=True)
    backend = Column(String)
    description = Column(String)
    # type of service, can be compute, storage, or general
    service = Column(String)


class Project(Base):
    __tablename__ = 'project'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    # identifier recognozied by the authorization provider
    auth_id = Column(String, unique=True)
    description = Column(String)
    parent_id = Column(Integer, ForeignKey('project.id'))
    parent = relationship('Project', backref='sub_projects', remote_side=[id])
    buckets = association_proxy(
        'project_to_buckets',
        'bucket')

    def __str__(self):
        str_out = {
            'id': self.id,
            'name': self.name,
            'auth_id': self.auth_id,
            'description': self.description,
            'parent_id': self.parent_id
        }
        return json.dumps(str_out)

    def __repr__(self):
        return self.__str__()


class ProjectToBucket(Base):
    __tablename__ = 'project_to_bucket'

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    project = relationship(Project, backref='project_to_buckets')

    bucket_id = Column(Integer, ForeignKey('bucket.id'))

    bucket = relationship('Bucket', backref='project_to_buckets')
    privilege = Column(ARRAY(String))


class ComputeAccess(Base):
    __tablename__ = 'compute_access'

    id = Column(Integer, primary_key=True)

    # compute access can be linked to a project/research group/user
    project_id = Column(Integer, ForeignKey('project.id'))
    project = relationship('Project', backref='compute_access')

    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='compute_access')

    group_id = Column(Integer, ForeignKey('research_group.id'))
    research_group = relationship('ResearchGroup', backref='compute_access')

    provider_id = Column(Integer, ForeignKey('cloud_provider.id'))
    provider = relationship('CloudProvider', backref='compute_access')

    instances = Column(Integer)
    cores = Column(Integer)
    ram = Column(BigInteger)
    floating_ips = Column(Integer)
    additional_info = Column(JSONB)


class StorageAccess(Base):
    '''
    storage access from a project/research group/user to a cloud_provider
    the project/group/user should be mutually exclusive
    '''
    __tablename__ = 'storage_access'

    __table_args__ = (
        CheckConstraint(
            'user_id is NULL or group_id is NULL or project_id is NULL',
            name='check_storage_subject'),
    )
    id = Column(Integer, primary_key=True)

    project_id = Column(Integer, ForeignKey('project.id'))
    project = relationship('Project', backref='storage_access')

    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='storage_access')

    group_id = Column(Integer, ForeignKey('research_group.id'))
    research_group = relationship('ResearchGroup', backref='storage_access')

    provider_id = Column(Integer, ForeignKey('cloud_provider.id'))
    provider = relationship('CloudProvider', backref='storage_access')

    max_objects = Column(BigInteger)
    max_size = Column(BigInteger)
    max_buckets = Column(Integer)
    additional_info = Column(JSONB)


class EventLog(Base):
    __tablename__ = 'event_log'

    id = Column(Integer, primary_key=True)
    action = Column(String)
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=text('now()'))
    target = Column(String)
    target_type = Column(String)
    description = Column(String)


class Organization(Base):
    __tablename__ = 'organization'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)


class Department(Base):
    __tablename__ = 'department'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)

    org_id = Column(Integer, ForeignKey('organization.id'))
    organization = relationship('Organization', backref='departments')


# application related tables

class Application(Base):
    __tablename__ = 'application'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id))
    resources_granted = Column(ARRAY(String))  # eg: ['compute', 'storage']
    certificates_uploaded = relationship(
        'Certificate',
        backref='user',
    )
    message = Column(String)


class Certificate(Base):
    __tablename__ = 'certificate'

    id = Column(Integer, primary_key=True)
    application_id = Column(Integer, ForeignKey('application.id'))
    name = Column(String(40))
    extension = Column(String)
    data = Column(LargeBinary)

    @property
    def filename(self):
        return '{}.{}'.format(self.name, self.extension)


class S3Credential(Base):
    __tablename__ = 's3credential'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='s3credentials')

    access_key = Column(String)

    timestamp = Column(
        DateTime, nullable=False, default=datetime.datetime.utcnow)
    expire = Column(Integer)


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
