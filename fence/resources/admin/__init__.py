"""
This module exposes the operations
available to modify the userdatamodel
and the storage system in a coherent
way.
All the operations return a dictionary
ready to be converted to a json.
"""

import fence.resources.userdatamodel as udm
import fence.resources.user as usr
from flask import current_app as capp
from fence.data_model.models import User
from flask_sqlalchemy_session import current_session
import json

def get_project_by_name(project_name):
    """
    Return the information associated with a project
    Returns a dictionary.
    """
    return udm.get_project_by_name(current_session, project_name)

def create_project_by_name(projectname, authid, storageaccesses):
    """
    Create a project with the specified auth_id and
    storage access.
    Returns a dictionary.
    """
    if udm.create_project(current_session, projectname, authid, storageaccesses):
        return {'result': 'success'}

def delete_project_by_name(project_name):
    """
    Remove a project. All buckets must be deleted
    before this oepration can be called.
    Returns a dictionary.
    """
    response = udm.delete_project_by_name(current_session, project_name)
    if response["result"] == "success":
        for user in response["users_to_remove"]:
            capp.storage_manager.delete_user(user[0].backend, user[1])
        return {"result": "success"}

def get_provider_by_name(provider_name):
    """
    Return all the information associated with
    a provider.
    Returns a dictionary.
    """
    return udm.get_provider_by_name(current_session, provider_name)

def create_provider_by_name(
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
    return udm.create_provider(
        current_session,
        provider_name,
        backend,
        service,
        endpoint,
        description
    )

def delete_provider_by_name(provider_name):
    """
    Remove a cloud provider from the database.
    All projects associated with it should be removed
    prior to calling this function.
    Returns a dictionary.
    """
    return udm.delete_provider_by_name(current_session, provider_name)

def connect_user_to_project(usr, project=None):
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

def connect_user_to_group(usr, group=None):
    pass

def create_user(username, projects=[], groups=[]):
    """
    Create a user for all the projects or groups in the list.
    If the user already exists, to avoid unadvertedly changing it, we suggest update
    Returns a dictionary.
    """
    usr = current_session.query(User).filter(
        User.username == username).first()
    if usr:
        msg = {"Error": ("user already exist. If this is not a"
               " mistake, please, retry using update")}
        return msg
    else:
        usr = User(username=username, active=True)
        current_session.add(usr)
        current_session.flush() 
        responses = []
        responses.append("User correctly created")
        for proj in projects:
            response = connect_user_to_project(usr, project=proj)
            responses.append(response)
        for grp in groups:
            response = connect_user_to_group(usr, group=grp)
            responses.append(response)
        return {"result": responses}

def delete_user(username):
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

def create_bucket_on_project_by_name(project_name, bucket_name, provider_name):
    """
    Create a bucket on userdatamodel database and
    on the cloud provider and associate it with the project.
    Returns a dictionary.
    """
    response = udm.create_bucket_on_project_by_name(
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

def delete_bucket_on_project_by_name(project_name, bucket_name):
    """
    Remove a bucket from a project, both on the userdatamodel
    and on the storage associated with that bucket.
    Returns a dictionary.
    """
    response = udm.delete_bucket_on_project_by_name(
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

def list_buckets_on_project_by_name(project_name):
    """
    Retrieve the buckets associated with a project.
    Returns a dictionary.
    """
    return udm.list_buckets_on_project_by_name(current_session, project_name)


def create_group(groupname, lead):
    """
    Creates a group and returns it
    """
    resp = usr.get_info_by_username(lead)
    lead_id = json.loads(resp.response[0])['user_id']
    return udm.create_group(groupname, lead_id)

def delete_group(groupname):
    """
    Creates a group and returns it
    """
    udm.clear_users_in_group(groupname)
    udm.clear_projects_in_group(groupname)
    udm.delete_group(groupname)
    return {'result': 'success'}
