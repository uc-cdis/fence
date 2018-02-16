import os
import tests
import uuid
import tests.utils.oauth2
from fence.models import User, Project, AccessPrivilege

from datetime import datetime, timedelta
from flask import current_app as capp


def read_file(filename):
    """Read the contents of a file in the tests directory."""
    root_dir = os.path.dirname(os.path.realpath(tests.__file__))
    with open(os.path.join(root_dir, filename), 'r') as f:
        return f.read()


def create_user(users, db_session, is_admin=False):
    s = db_session
    for username in users.keys():
        user = s.query(User).filter(User.username == username).first()
        if not user:
            user = User(username=username, is_admin=is_admin)
            s.add(user)
        for project_data in users[username]['projects']:
            privilege = project_data['privilege']
            auth_id = project_data['auth_id']
            p_name = project_data.get('name', auth_id)

            project = s.query(Project).filter(
                Project.auth_id == auth_id).first()
            if not project:
                project = Project(name=p_name, auth_id=auth_id)
                s.add(project)
            ap = (
                s
                .query(AccessPrivilege)
                .join(AccessPrivilege.project)
                .join(AccessPrivilege.user)
                .filter(Project.name == p_name, User.username == user.username)
                .first()
            )
            if not ap:
                ap = AccessPrivilege(
                    project=project, user=user, privilege=privilege
                )
                s.add(ap)
            else:
                ap.privilege = privilege
    return user.id, user.username


def new_jti():
    """
    Return a fresh jti (JWT token ID).
    """
    return str(uuid.uuid4())


def iat_and_exp():
    """
    Return ``iat`` and ``exp`` claims for a JWT.
    """
    now = datetime.now()
    iat = int(now.strftime('%s'))
    exp = int((now + timedelta(seconds=60)).strftime('%s'))
    return (iat, exp)


def default_claims():
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ['openid', 'user']
    iss = 'https://user-api.test.net'
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'pur': 'access',
        'aud': aud,
        'sub': '1234',
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
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
    aud = ['access', 'data', 'user', 'openid']
    iss = capp.config['BASE_URL']
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'aud': aud,
        'sub': user_id,
        'pur': 'access',
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
    aud = ['access', 'data', 'user', 'openid']
    iss = capp.config['BASE_URL']
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'aud': aud,
        'sub': user_id,
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'pur': 'access',
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
    aud = ['access', 'data', 'user', 'openid']
    iss = capp.config['BASE_URL']
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        'aud': aud,
        'sub': user_id,
        'iss': iss,
        'pur': 'access',
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


class FakeFlaskRequest(object):
    """
    Make a fake ``flask.request`` to patch in tests.
    """

    def __init__(self, method='GET', args=None, form=None):
        self.method = method
        self.args = args
        self.form = form
