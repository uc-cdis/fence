import os
import time
import urllib.parse
import uuid

from flask import current_app

from fence.config import config

from fence.models import (
    User,
    Project,
    AccessPrivilege,
    UserToGroup,
    Group,
    CloudProvider,
    Bucket,
    StorageAccess,
    ProjectToBucket,
    UserToBucket,
    query_for_user,
)

import tests
import tests.utils.oauth2


def read_file(filename):
    """Read the contents of a file in the tests directory."""
    root_dir = os.path.dirname(os.path.realpath(tests.__file__))
    with open(os.path.join(root_dir, filename), "r") as f:
        return f.read()


def create_user(users, db_session, is_admin=False):
    s = db_session
    for username in list(users.keys()):
        user = query_for_user(session=s, username=username)
        if not user:
            user = User(username=username, is_admin=is_admin)
            s.add(user)
        for project_data in users[username]["projects"]:
            privilege = project_data["privilege"]
            auth_id = project_data["auth_id"]
            p_name = project_data.get("name", auth_id)

            project = s.query(Project).filter(Project.auth_id == auth_id).first()
            if not project:
                project = Project(name=p_name, auth_id=auth_id)
                s.add(project)
            ap = (
                s.query(AccessPrivilege)
                .join(AccessPrivilege.project)
                .join(AccessPrivilege.user)
                .filter(Project.name == p_name, User.username == user.username)
                .first()
            )
            if not ap:
                ap = AccessPrivilege(project=project, user=user, privilege=privilege)
                s.add(ap)
            else:
                ap.privilege = privilege

    return user.id, user.username


def create_awg_user(users, db_session):
    s = db_session
    for username in list(users.keys()):
        user = query_for_user(session=s, username=username)
        if not user:
            user = User(username=username)
            s.add(user)

        projects = {}
        for project_data in users[username]["projects"]:
            auth_id = project_data["auth_id"]
            p_name = project_data.get("name", auth_id)

            project = s.query(Project).filter(Project.auth_id == auth_id).first()
            if not project:
                project = Project(name=p_name, auth_id=auth_id)
                s.add(project)
            projects[p_name] = project

        groups = users[username].get("groups", [])
        for group in groups:
            group_name = group["name"]
            group_desc = group["description"]
            grp = s.query(Group).filter(Group.name == group_name).first()
            if not grp:
                grp = Group()
                grp.name = group_name
                grp.description = group_desc
                s.add(grp)
                s.flush()
            UserToGroup(group=grp, user=user)
            for projectname in group["projects"]:
                gap = (
                    s.query(AccessPrivilege)
                    .join(AccessPrivilege.project)
                    .join(AccessPrivilege.group)
                    .filter(Project.name == projectname, Group.name == group_name)
                    .first()
                )
                if not gap:
                    project = projects[projectname]
                    gap = AccessPrivilege(project_id=project.id, group_id=grp.id)
                    s.add(gap)
                    s.flush()
                ap = (
                    s.query(AccessPrivilege)
                    .join(AccessPrivilege.project)
                    .join(AccessPrivilege.user)
                    .filter(Project.name == projectname, User.username == user.username)
                    .first()
                )
                privilege = {"read"}
                if not ap:
                    project = projects[projectname]
                    ap = AccessPrivilege(
                        project=project, user=user, privilege=privilege
                    )
                    s.add(ap)
                    s.flush()
    return user.id, user.username


def create_providers(data, db_session):
    s = db_session
    providers = data["providers"]
    for provider in providers:
        prov = CloudProvider()
        prov.name = provider["name"]
        prov.backend = provider["backend"]
        prov.service = provider["service"]
        s.add(prov)
        s.flush

    for name, user in list(data["users"].items()):
        new_user = User()
        new_user.username = name
        new_user.email = user["email"]
        new_user.is_admin = user["is_admin"]
        s.add(new_user)
        user["id"] = new_user.id

    for project in data["projects"]:
        new_project = Project()
        new_project.name = project["name"]
        s.add(new_project)
        for storage in project["storage_access"]:
            provider = s.query(CloudProvider).filter_by(name=storage).first()
            if provider:
                new_storage_access = StorageAccess(
                    provider_id=provider.id, project_id=new_project.id
                )
                s.add(new_storage_access)

        for bucket in project["buckets"]:
            new_bucket = Bucket()
            new_bucket.name = bucket["name"]
            provider = s.query(CloudProvider).filter_by(name=bucket["provider"]).first()
            new_bucket.provider_id = provider.id
            s.add(new_bucket)
            s.flush()
            project_to_bucket = ProjectToBucket()
            project_to_bucket.bucket_id = new_bucket.id
            project_to_bucket.project_id = new_project.id
            s.add(project_to_bucket)
            s.flush()
        for user in project["users"]:
            access = AccessPrivilege()
            access.user_id = data["users"][user["name"]]["id"]
            access.project_id = new_project.id
            s.add(access)


def create_awg_groups(data, db_session):
    s = db_session
    projects = {}
    for project_data in data["projects"]:
        auth_id = project_data["auth_id"]
        p_name = project_data.get("name", auth_id)

        project = s.query(Project).filter(Project.auth_id == auth_id).first()
        if not project:
            project = Project(name=p_name, auth_id=auth_id)
            s.add(project)
        projects[p_name] = project

    for group in data["groups"]:
        group_name = group["name"]
        group_desc = group["description"]
        grp = s.query(Group).filter(Group.name == group_name).first()
        if not grp:
            grp = Group()
            grp.name = group_name
            grp.description = group_desc
            s.add(grp)

        for projectname in group["projects"]:
            gap = (
                s.query(AccessPrivilege)
                .join(AccessPrivilege.project)
                .join(AccessPrivilege.group)
                .filter(Project.name == projectname, Group.name == group_name)
                .first()
            )
            if not gap:
                project = projects[projectname]
                gap = AccessPrivilege(project_id=project.id, group_id=grp.id)
                s.add(gap)
                s.flush()


def new_jti():
    """Return a fresh JTI (JWT token ID)."""
    return str(uuid.uuid4())


def iat_and_exp():
    """
    Return ``iat`` and ``exp`` claims for a JWT.
    """
    iat = int(time.time())
    exp = iat + 600
    return (iat, exp)


def default_claims():
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ["openid", "user"]
    iss = "https://user-api.test.net"
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        "pur": "access",
        "aud": aud,
        "sub": "1234",
        "iss": iss,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": "",
        "context": {
            "user": {
                "name": "test-user",
                "projects": [],
                "google": {"proxy_group": None},
            }
        },
    }


def unauthorized_context_claims(user_name, user_id):
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ["access", "data", "user", "openid"]
    iss = config["BASE_URL"]
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        "aud": aud,
        "sub": user_id,
        "pur": "access",
        "iss": iss,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": "",
        "context": {
            "user": {
                "name": "test",
                "projects": {
                    "phs000178": ["read"],
                    "phs000234": ["read", "read-storage"],
                },
                "google": {"proxy_group": None},
            }
        },
    }


def authorized_download_context_claims(user_name, user_id):
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ["access", "data", "user", "openid"]
    iss = config["BASE_URL"]
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        "aud": aud,
        "sub": user_id,
        "iss": iss,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": "",
        "pur": "access",
        "context": {
            "user": {
                "name": user_name,
                "projects": {
                    "phs000178": ["read"],
                    "phs000218": ["read", "read-storage"],
                },
                "google": {"proxy_group": None},
            }
        },
    }


def authorized_service_account_management_claims(user_name, user_id, client_id):
    """
    Return a generic claims dictionary to put in a JWT

    Return:
        dict: dictionary of claims
    """
    aud = ["access", "data", "user", "openid", "google_link", "google_service_account"]
    iss = config["BASE_URL"]
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        "aud": aud,
        "sub": user_id,
        "iss": iss,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": client_id,
        "pur": "access",
        "context": {
            "user": {
                "name": user_name,
                "projects": {
                    "phs000178": ["read"],
                    "phs000218": ["read", "read-storage"],
                },
            }
        },
    }


def authorized_download_credentials_context_claims(
    user_name, user_id, client_id, google_proxy_group_id=None
):
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = [
        "access",
        "data",
        "user",
        "openid",
        "credentials",
        "google_link",
        "google_credentials",
    ]
    iss = config["BASE_URL"]
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        "aud": aud,
        "sub": user_id,
        "iss": iss,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": client_id,
        "pur": "access",
        "context": {
            "user": {
                "name": user_name,
                "projects": {
                    "phs000178": ["read"],
                    "phs000218": ["read", "read-storage"],
                },
                "google": {"proxy_group": google_proxy_group_id},
            }
        },
    }


def authorized_upload_context_claims(user_name, user_id):
    """
    Return a generic claims dictionary to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    aud = ["access", "data", "user", "openid"]
    iss = config["BASE_URL"]
    jti = new_jti()
    iat, exp = iat_and_exp()
    return {
        "aud": aud,
        "sub": user_id,
        "iss": iss,
        "pur": "access",
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": "test-client",
        "context": {
            "user": {
                "name": user_name,
                "projects": {
                    "phs000178": ["read"],
                    "phs000218": ["read", "write-storage"],
                },
                "google": {"proxy_group": None},
            }
        },
    }


class FakeFlaskRequest(object):
    """
    Make a fake ``flask.request`` to patch in tests.
    """

    def __init__(self, method="GET", args=None, form=None):
        self.method = method
        self.args = args
        self.form = form


def remove_qs(url):
    """
    Remove the query string from a url.
    """
    return urllib.parse.urljoin(url, urllib.parse.urlparse(url).path)
