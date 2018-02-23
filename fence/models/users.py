"""
Models relating to users, including groups and organizations
"""
import json

from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Column
from sqlalchemy import Boolean
from sqlalchemy import text
from sqlalchemy import UniqueConstraint
from sqlalchemy import Index
from sqlalchemy import CheckConstraint
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.orm import backref
from sqlalchemy.schema import ForeignKey
from sqlalchemy.orm.collections import MappedCollection, collection

from fence.models._base import Base


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
        if key in self:
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

    groups = association_proxy(
        'user_to_groups',
        'group')

    group_privileges = relationship(
        'AccessPrivilege', primaryjoin='user_to_group.c.user_id==User.id',
        secondary='join(AccessPrivilege, Group, AccessPrivilege.group_id==Group.id).'
                  'join(user_to_group, Group.id == user_to_group.c.group_id)',
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

    group_id = Column(Integer, ForeignKey('Group.id'))
    group = relationship('Group', backref='accesses_privilege')

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


class Group(Base):
    __tablename__ = 'Group'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)

    users = association_proxy(
        'user_to_groups',
        'user')


class UserToGroup(Base):
    '''
    Edge table between user and group
    '''
    __tablename__ = 'user_to_group'
    user_id = Column('user_id', Integer, ForeignKey('User.id'), primary_key=True)
    user = relationship(User, backref='user_to_groups')

    group_id = Column('group_id', Integer, ForeignKey('Group.id'), primary_key=True)
    group = relationship('Group', backref='user_to_groups')

    roles = Column('roles', ARRAY(String))


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
