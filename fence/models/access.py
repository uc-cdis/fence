"""
Models relating to privledges and access
"""
import json

from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Column
from sqlalchemy import BigInteger
from sqlalchemy import CheckConstraint
from sqlalchemy import LargeBinary
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.schema import ForeignKey

from fence.models._base import Base
from fence.models.users import User


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


class ComputeAccess(Base):
    __tablename__ = 'compute_access'

    id = Column(Integer, primary_key=True)

    # compute access can be linked to a project/research group/user
    project_id = Column(Integer, ForeignKey('project.id'))
    project = relationship('Project', backref='compute_access')

    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship('User', backref='compute_access')

    group_id = Column(Integer, ForeignKey('Group.id'))
    group = relationship('Group', backref='compute_access')

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

    group_id = Column(Integer, ForeignKey('Group.id'))
    group = relationship('Group', backref='storage_access')

    provider_id = Column(Integer, ForeignKey('cloud_provider.id'))
    provider = relationship('CloudProvider', backref='storage_access')

    max_objects = Column(BigInteger)
    max_size = Column(BigInteger)
    max_buckets = Column(Integer)
    additional_info = Column(JSONB)


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


class UserToBucket(Base):
    __tablename__ = 'user_to_bucket'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey(User.id))
    user = relationship(
        User,
        backref=backref('user_to_buckets', cascade='all, delete-orphan')
    )

    bucket_id = Column(Integer, ForeignKey('bucket.id'))

    bucket = relationship(
        'Bucket',
        backref=backref('user_to_buckets', cascade='all, delete-orphan')
    )
    privilege = Column(ARRAY(String))


class ProjectToBucket(Base):
    __tablename__ = 'project_to_bucket'

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('project.id'))
    project = relationship(
        Project,
        backref=backref('project_to_buckets', cascade='all, delete-orphan')
    )

    bucket_id = Column(Integer, ForeignKey('bucket.id'))

    bucket = relationship('Bucket', backref='project_to_buckets')
    privilege = Column(ARRAY(String))
