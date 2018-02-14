from fence.resources import (
    userdatamodel as udm,
    project as pj,
    group as gp,
    user as us,
    provider as pv
)

from flask import current_app as capp
from fence.data_model.models import User, Group
from fence.errors import NotFound
import json
from fence.errors import UserError




#### USERS ####

def connect_user_to_project(current_session, usr, project=None):
    """
    Create a user name for the specific project.
    Returns a dictionary.
    """
    response = udm.create_user_by_username_project(
        current_session,
        usr,
        project
    )
    if response["result"] == "success":
        proj = response["project"]
        priv = response["privileges"]
        cloud_providers = udm.get_cloud_providers_from_project(current_session, proj.id)
        response = []
        for provider in cloud_providers:
            capp.storage_manager.get_or_create_user(provider.backend, usr)
            buckets = udm.get_buckets_by_project_cloud_provider(
                current_session, proj.id, provider.id)
            for bucket in buckets["buckets"]:
                try:
                    capp.storage_manager.update_bucket_acl(
                        provider.backend,
                        bucket,
                        (usr, priv.privilege))
                    msg = ("Success: user access"
                           " created for a bucket in the project {0}")
                    response.append(msg.format(proj.name))
                except:
                    msg = ("Error user access not"
                           " created for project {0} and bucket {2}")
                    response.append(
                        msg.format(proj.name, bucket["name"]))
    return response

def get_user_info(current_session, username):
    return us.get_user_info(current_session, username)


def get_all_users(current_session):
    users = udm.get_all_users(current_session)
    users_names = []
    for user in users:
        new_user = {}
        new_user['name'] = user.username
        if user.is_admin:
            new_user['role'] = "admin"
        else:
            new_user['role'] = "user"
        users_names.append(new_user)
    return {"users": users_names}


def get_user_groups(current_session, username):
    return us.get_user_groups(current_session, username)


def create_user(current_session, username, role, email):
    """
    Create a user for all the projects or groups in the list.
    If the user already exists, to avoid unadvertedly changing it, we suggest update
    Returns a dictionary.
    """
    try:
        usr = us.get_user(current_session, username)
        raise UserError(("Error: user already exist. If this is not a"
               " mistake, please, retry using update"))
        return msg
    except NotFound:
        is_admin = True if role == "admin" else False
        email_add = email
        usr = User(username=username, active=True, is_admin=is_admin, email=email_add)
        current_session.add(usr)
        current_session.flush()
        return us.get_user_info(current_session, username)

def update_user(current_session, username, role, email):
    usr = us.get_user(current_session, username)
    usr.email = email or usr.email
    if role:
        is_admin = True if role == 'admin' else False
    else:
        is_admin = usr.is_admin
    usr.is_admin = is_admin
    current_session.flush()
    return us.get_user_info(current_session, username)


def add_user_to_projects(current_session, username, projects=[]):
    usr = us.get_user(current_session, username)
    responses = []
    for proj in projects:
        try:
            response = connect_user_to_project(current_session, usr, proj)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    return {"result": responses}

def delete_user(current_session, username):
    """
    Remove a user from both the userdatamodel
    and the assciated storage for that project/bucket.
    Returns a dictionary.
    """
    response = udm.delete_user_by_username(current_session, username)
    if response["result"] == "success":
        for provider in response["providers"]:
            capp.storage_manager.delete_user(provider.backend, response["user"])
        return {"result": "success"}


def get_group_projects(current_session, groupname):
    return gp.get_group_projects(current_session, groupname)
