from fence.resources import project as pj
from flask import current_app

__all__ = [
    "get_project_info",
    "get_all_projects",
    "create_project",
    "delete_project",
    "create_bucket_on_project",
    "delete_bucket_on_project",
    "list_buckets_on_project",
]


def get_project_info(current_session, project_name):
    """
    Return the information associated with a project
    Returns a dictionary.
    """
    return pj.get_project_info(current_session, project_name)


def get_all_projects(current_session):
    """
    Return the information associated with a project
    Returns a dictionary.
    """
    return pj.get_all_projects(current_session)


def create_project(current_session, projectname, authid, storageaccesses):
    """
    Create a project with the specified auth_id and
    storage access.
    Returns a dictionary.
    """
    if pj.create_project(current_session, projectname, authid, storageaccesses):
        return {"result": "success"}


def delete_project(current_session, project_name):
    """
    Remove a project. All buckets must be deleted
    before this oepration can be called.
    Returns a dictionary.
    """
    response = pj.delete_project(current_session, project_name)
    if response["result"] == "success":
        for user in response["users_to_remove"]:
            current_app.storage_manager.delete_user(user[0].backend, user[1])
        return {"result": "success"}


def create_bucket_on_project(current_session, project_name, bucket_name, provider_name):
    """
    Create a bucket on userdatamodel database and
    on the cloud provider and associate it with the project.
    Returns a dictionary.
    """
    response = pj.create_bucket_on_project(
        current_session, project_name, bucket_name, provider_name
    )
    project = pj.get_project(current_session, project_name)
    if response["result"] == "success":
        current_app.storage_manager.create_bucket(
            response["provider"].name, current_session, response["bucket"].name, project
        )
        for user_pair in response["users_to_update"]:
            current_app.storage_manager.update_bucket_acl(
                response["provider"].name,
                response["bucket"],
                (user_pair[0], user_pair[1]),
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
    response = pj.delete_bucket_on_project(current_session, project_name, bucket_name)
    if response["result"] == "success":
        current_app.storage_manager.delete_bucket(
            response["provider"].name, bucket_name
        )
        return {"result": "success"}
    else:
        current_app.storage_manager.delete_bucket(
            response["provider"].name, bucket_name
        )
        return {"result": response["result"]}


def list_buckets_on_project(current_session, project_name):
    """
    Retrieve the buckets associated with a project.
    Returns a dictionary.
    """
    return pj.list_buckets_on_project(current_session, project_name)
