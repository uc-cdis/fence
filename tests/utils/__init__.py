import os
import time
import uuid

import flask
from userdatamodel.driver import SQLAlchemyDriver

from fence.models import User, Project, AccessPrivilege


def read_file(filename):
    """Read the contents of a file in the tests directory."""
    root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    with open(os.path.join(root_dir, filename), 'r') as f:
        return f.read()


def create_user(users, DB, is_admin=False):
    driver = SQLAlchemyDriver(DB)
    with driver.session as session:
        for username in users.keys():
            user = (
                session
                .query(User)
                .filter(User.username == username)
                .first()
            )
            if not user:
                user = User(username=username, is_admin=is_admin)
                session.add(user)
            for project_data in users[username]['projects']:
                privilege = project_data['privilege']
                auth_id = project_data['auth_id']
                p_name = project_data.get('name', auth_id)
                project = (
                    session
                    .query(Project)
                    .filter(Project.auth_id == auth_id)
                    .first()
                )
                if not project:
                    project = Project(name=p_name, auth_id=auth_id)
                    session.add(project)
                access_privilege = (
                    session
                    .query(AccessPrivilege)
                    .join(AccessPrivilege.project)
                    .join(AccessPrivilege.user)
                    .filter(
                        Project.name == p_name,
                        User.username == user.username,
                    )
                    .first()
                )
                if not access_privilege:
                    access_privilege = AccessPrivilege(
                        project=project, user=user, privilege=privilege
                    )
                    session.add(access_privilege)
                else:
                    access_privilege.privilege = privilege
        session.commit()
    return user.id, user.username


def new_jti():
    """
    Return a fresh jti (JWT token ID).
    """
    return str(uuid.uuid4())


def iat_and_exp(expires_in=600):
    """
    Return ``iat`` and ``exp`` claims for a JWT.
    """
    iat = int(time.time())
    exp = iat + expires_in
    return (iat, exp)


def default_claims():
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['access', 'user']
    iss = flask.current_app.config['HOSTNAME']
    jti = new_jti()
    iat, exp = iat_and_exp()
    azp = ''
    return {
        'aud': aud,
        'sub': '1234',
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'azp': azp,
        'context': {
            'user': {
                'name': 'test-user',
                'projects': [
                ],
            },
        },
    }


def unauthorized_context_claims(user_name, user_id):
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['access', 'data', 'user']
    iss = flask.current_app.config['HOSTNAME']
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'aud': aud,
        'sub': user_id,
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': 'test',
                'projects': {
                    "phs000178": ["read"],
                    "phs000234": ["read", "read-storage"],
                },
            },
        },
    }


def authorized_download_context_claims(user_name, user_id):
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['access', 'data', 'user']
    iss = flask.current_app.config['HOSTNAME']
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'aud': aud,
        'sub': user_id,
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': user_name,
                'projects': {
                    "phs000178": ["read"],
                    "phs000218": ["read", "read-storage"],
                },
            },
        },
    }


def authorized_upload_context_claims(user_name, user_id):
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['access', 'data', 'user']
    iss = flask.current_app.config['HOSTNAME']
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'aud': aud,
        'sub': user_id,
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': user_name,
                'projects': {
                    "phs000178": ["read"],
                    "phs000218": ["read", "write-storage"],
                },
            },
        },
    }
