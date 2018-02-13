"""
This module exposes the operations
available to modify the userdatamodel
and the storage system in a coherent
way.
All the operations return a dictionary
ready to be converted to a json.
"""

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



def get_project_info(current_session, project_name):
    """
    Return the information associated with a project
    Returns a dictionary.
    """
    return pj.get_project_info(current_session, project_name)

def create_project(current_session, projectname, authid, storageaccesses):
    """
    Create a project with the specified auth_id and
    storage access.
    Returns a dictionary.
    """
    if pj.create_project(current_session, projectname, authid, storageaccesses):
        return {'result': 'success'}

def delete_project(current_session, project_name):
    """
    Remove a project. All buckets must be deleted
    before this oepration can be called.
    Returns a dictionary.
    """
    response = pj.delete_project(current_session, project_name)
    if response["result"] == "success":
        for user in response["users_to_remove"]:
            capp.storage_manager.delete_user(user[0].backend, user[1])
        return {"result": "success"}


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

def create_bucket_on_project(current_session, project_name, bucket_name, provider_name):
    """
    Create a bucket on userdatamodel database and
    on the cloud provider and associate it with the project.
    Returns a dictionary.
    """
    response = pj.create_bucket_on_project_by_name(
        current_session,
        project_name,
        bucket_name,
        provider_name
    )
    if response["result"] == "success":
        capp.storage_manager.create_bucket(
            response["provider"].backend,
            response["bucket"].name
        )
        for user_pair in response["users_to_update"]:
            capp.storage_manager.update_bucket_acl(
                response["provider"].backend,
                response["bucket"],
                (user_pair[0], user_pair[1])
            )
        return {"result": "success"}
    else:
        return response

def delete_bucket_on_project(current_session, project_name, bucket_name):
    """
    Remove a bucket from a project, both on the userdatamodel
    and on the storage associated with that bucket.
    Returns a dictionary.
    """
    response = pj.delete_bucket_on_project_by_name(
        current_session,
        project_name,
        bucket_name
    )
    if response["result"] == "success":
        capp.storage_manager.delete_bucket(
            response["provider"].backend,
            bucket_name
        )
        return {"result": "success"}
    else:
        capp.storage_manager.delete_bucket(
            response["provider"].backend,
            bucket_name
        )
        return {"result": response["result"]}

def list_buckets_on_project(current_session, project_name):
    """
    Retrieve the buckets associated with a project.
    Returns a dictionary.
    """
    return pj.list_buckets_on_project(current_session, project_name)


def create_group(current_session, groupname):
    """
    Creates a group and returns it
    """
    return gp.create_group(current_session, groupname)

def delete_group(current_session, groupname):
    """
    Deletes a group
    """
    gp.clear_users_in_group(current_session, groupname)
    gp.clear_projects_in_group(current_session, groupname)
    gp.delete_group(current_session, groupname)
    return {'result': 'success'}

def get_user_groups(current_session, username):
    return us.get_user_groups(current_session, username)


def get_group(current_session, groupname):
    group = gp.get_group(current_session, groupname)
    if not group:
        raise UserError("Error: group doesn' exist")
    else:
        return {"name": group.name}

def get_all_groups(current_session):
    groups = gp.get_all_groups(current_session)
    groups_list = []
    for group in groups:
        groups_list.append(group.name)
    return {"groups": groups_list}


def get_group_users(current_session, groupname):
    users = gp.get_group_users(current_session, groupname)
    users_names = []
    for user in users:
        users_names.append(user.username)
    return {"users": users_names}

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

def connect_user_to_group(current_session, usr, group=None):
    grp = gp.get_group(current_session, group)
    if not grp:
        raise UserError(("Group {0} doesn't exist".format(group)))
    else:
        return udm.connect_user_to_group(current_session, usr, grp)

def add_user_to_groups(current_session, username, groups=[]):
    usr = us.get_user(curent_session, username)
    responses = []
    for groupname in groups:
        try:
            response = connect_user_to_group(current_session, usr, groupname)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    return {"result": responses}

def disconnect_user_from_group(current_session, usr, groupname):
    grp = gp.get_group(current_session, groupname)
    if not grp:
        return {"warning": ("Group {0} doesn't exist".format(group))}
    else:
        return udm.remove_user_from_group(current_session, usr, grp)
    
def remove_user_from_groups(current_session, username, groups=[]):
    usr = us.get_user(current_session, username)
    responses = []
    for groupname in groups:
        try:
            response = disconnect_user_from_group(current_session, usr, groupname)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    return {"result": responses}


def connect_project_to_group(current_session, grp, project=None):
    prj = pj.get_project(current_session, project)
    if not prj:
        raise UserError(("Project {0} doesn't exist".format(project)))
    else:
        return udm.connect_project_to_group(current_session, grp, prj)

def add_projects_to_group(current_session, groupname, projects=[]):
    grp = gp.get_group(current_session, groupname)
    if not grp:
        raise UserError ("Error: group does not exist")
    else:
        responses = []
        for proj in projects:
            try:
                response = connect_project_to_group(grp, proj)
                responses.append(response)
            except Exception as e:
                current_session.rollback()
                raise e
        return {"result": responses}


def disconnect_project_from_group(current_session, grp, projectname):
    prj = pj.get_project(current_session, projectname)
    if not prj:
        return {"warning": ("Project {0} doesn't exist".format(projectname))}
    else:
        return udm.remove_project_from_group(current_session, grp, prj)
    

def remove_projects_from_group(current_session, groupname, projects=[]):
    grp = gp.get_group(current_session, groupname)
    if not grp:
        raise UserError ("Error: group does not exist")
    else:
        responses = []
        for proj in projects:
            try:
                response = disconnect_project_from_group(current_session, grp, proj)
                responses.append(response)
            except Exception as e:
                current_session.rollback()
                raise e
        return {"result": responses}


#### CLOUD PROVIDER ####


def get_provider(current_session, provider_name):
    """
    Return all the information associated with
    a provider.
    Returns a dictionary.
    """
    return pv.get_provider(current_session, provider_name)

def create_provider(
        current_session,
        provider_name,
        backend=None,
        service=None,
        endpoint=None,
        description=None):
    """
    Create a provider in the userdatamodel
    database.
    Returns a dictionary.
    """
    return pv.create_provider(
        current_session,
        provider_name,
        backend,
        service,
        endpoint,
        description
    )

def delete_provider_by_name(current_session, provider_name):
    """
    Remove a cloud provider from the database.
    All projects associated with it should be removed
    prior to calling this function.
    Returns a dictionary.
    """
    return udm.delete_provider(current_session, provider_name)
