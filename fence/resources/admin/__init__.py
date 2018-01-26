"""
This module exposes the operations
available to modify the userdatamodel
and the storage system in a coherent
way.
All the operations return a dictionary
ready to be converted to a json.
"""

import fence.resources.userdatamodel as udm
from flask import current_app as capp
from fence.data_model.models import User
from flask_sqlalchemy_session import current_session

def get_project_by_name(project_name):
    """
    Return the information associated with a project
    Returns a dictionary.
    """
    return udm.get_project_by_name(project_name)

def create_project_by_name(projectname, authid, storageaccesses):
    """
    Create a project with the specified auth_id and
    storage access.
    Returns a dictionary.
    """
    return udm.create_project_by_name(projectname, authid, storageaccesses)

def delete_project_by_name(project_name):
    """
    Remove a project. All buckets must be deleted
    before this oepration can be called.
    Returns a dictionary.
    """
    response = udm.delete_project_by_name(project_name)
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
    return udm.get_provider_by_name(provider_name)

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
    return udm.create_provider_by_name(
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
    return udm.delete_provider_by_name(provider_name)

def create_user_by_username_project(username, project=None):
    """
    Create a user name for the specific project.
    Returns a dictionary.
    """
    #if the user doesn't exist, create it, otherwise we are updating it
    usr = current_session.query(User).filter(
        User.username == username).first()
    if not usr:
        usr = User(username=username, active=True)
        current_session.add(usr)
        current_session.flush()
    response = udm.create_user_by_username_project(
        usr,
        project
    )
    if response["result"] == "success":
        proj = response["project"]
        priv = response["privileges"]
        cloud_providers = udm.get_cloud_providers_from_project(proj.id)
        response = []
        for provider in cloud_providers:
            capp.storage_manager.get_or_create_user(provider.backend, usr)
            buckets = udm.get_buckets_by_project_cloud_provider(
                proj.id, provider.id)
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

def create_user_by_username(username, projects=[]):
    """
    Create a user for all the projects in the list.
    Returns a dictionary.
    """
    responses = []
    for proj in projects:
        response = create_user_by_username_project(username, project=proj)
        responses.append(response)
    return {"result": responses}

def delete_user_by_username(username):
    """
    Remove a user from both the userdatamodel
    and the assciated storage for that project/bucket.
    Returns a dictionary.
    """
    response = udm.delete_user_by_username(username)
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
    return udm.list_buckets_on_project_by_name(project_name)
