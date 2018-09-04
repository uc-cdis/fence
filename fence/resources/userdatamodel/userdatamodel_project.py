from sqlalchemy import func

from fence.errors import NotFound, UserError
from fence.models import (
    Project,
    StorageAccess,
    CloudProvider,
    ProjectToBucket,
    Bucket,
    User,
    AccessPrivilege,
    Group,
    UserToGroup,
)

__all__ = [
    "get_project",
    "create_project_with_dict",
    "create_project",
    "create_bucket_on_project",
    "get_project_info",
    "get_all_projects",
    "delete_project",
    "delete_bucket_on_project",
    "list_buckets_on_project",
    "get_cloud_providers_from_project",
    "get_buckets_by_project_cloud_provider",
    "get_user_project_access_privilege",
]


def get_project(current_session, projectname):
    return current_session.query(Project).filter_by(name=projectname).first()


def create_project_with_dict(current_session, project_data):
    """
    Create a project given a dict of all needed info
    Args:
        project_data (dict): dict of project info
    Return:
        None
    """
    auth_id = project_data["auth_id"]
    name = project_data.get("name") or auth_id
    storage_accesses = project_data.get("storage_accesses", [])
    project = create_project(
        current_session, name, auth_id, [sa["name"] for sa in storage_accesses]
    )
    for sa in storage_accesses:
        for bucket in sa.get("buckets", []):
            create_bucket_on_project(current_session, name, bucket, sa["name"])

    return project


def create_project(current_session, name, auth_id, storage_accesses):
    """
    Creates a project with an associated auth_id and storage access
    """
    new_project = Project(name=name, auth_id=auth_id)
    current_session.add(new_project)
    current_session.flush()
    for storage in storage_accesses:
        provider = (
            current_session.query(CloudProvider)
            .filter(CloudProvider.name == storage)
            .first()
        )
        if provider:
            new_storage_access = StorageAccess(
                provider_id=provider.id, project_id=new_project.id
            )
            current_session.add(new_storage_access)
        else:
            raise NotFound()
    return new_project


def create_bucket_on_project(current_session, project_name, bucket_name, provider_name):
    """
    Create a bucket and assign it to a project
    """
    project = (
        current_session.query(Project).filter(Project.name == project_name).first()
    )
    if not project:
        msg = "".join(["Project ", project_name, " not found"])
        raise NotFound(msg)
    provider = (
        current_session.query(CloudProvider)
        .filter(CloudProvider.name == provider_name)
        .first()
    )
    if not provider:
        msg = "".join(["Provider ", provider_name, " not found"])
        raise NotFound(msg)
    bucket = (
        current_session.query(Bucket)
        .filter(Bucket.name == bucket_name, Bucket.provider_id == provider.id)
        .first()
    )
    if not bucket:
        bucket = Bucket(name=bucket_name, provider_id=provider.id)
        current_session.add(bucket)
        current_session.flush()
        proj_to_bucket = ProjectToBucket(
            project_id=project.id, bucket_id=bucket.id, privilege=["owner"]
        )
        current_session.add(proj_to_bucket)
        # Find the users that need to be updated
        users_in_project = current_session.query(AccessPrivilege).filter(
            AccessPrivilege.project_id == project.id
        )
        users_to_update = []
        for row in users_in_project:
            usr = current_session.query(User).filter(User.id == row.user_id).first()
            users_to_update.append((usr, row.privilege))
        return {
            "result": "success",
            "provider": provider,
            "bucket": bucket,
            "users_to_update": users_to_update,
        }
    else:
        raise UserError("Error, name already in use for that storage system")


def get_project_info(current_session, project_name):
    """
    Get project info from userdatamodel
    from its name
    """
    proj = get_project(current_session, project_name)
    if not proj:
        msg = "".join(["Error: project ", project_name, " not found"])
        raise NotFound(msg)
    info = {
        "id": proj.id,
        "name": proj.name,
        "auth_id": proj.auth_id,
        "description": proj.description,
        "associated buckets": [],
    }
    buckets = current_session.query(ProjectToBucket).filter(
        ProjectToBucket.project_id == proj.id
    )
    for row in buckets:
        bucket = (
            current_session.query(Bucket).filter(Bucket.id == row.bucket_id).first()
        )
        info["associated buckets"].append(bucket.name)
    return info


def get_all_projects(current_session):
    projects = current_session.query(Project).all()
    projects_info = [
        get_project_info(current_session, project.name) for project in projects
    ]
    return {"projects": projects_info}


def delete_project(current_session, project_name):
    """
    Delete the project from the database
    The project should have no buckets in use
    """
    proj = current_session.query(Project).filter(Project.name == project_name).first()

    if not proj:
        return {"result": "error, project not found"}

    buckets = (
        current_session.query(ProjectToBucket)
        .filter(ProjectToBucket.project_id == proj.id)
        .first()
    )

    if buckets:
        msg = (
            "error, project still has buckets associated with it. Please"
            " remove those first and then retry."
        )
        return {"result": msg}

    storage_access = current_session.query(StorageAccess).filter(
        StorageAccess.project_id == proj.id
    )
    """
    Find the users that only belong to this project
    and store them to be removed
    """
    accesses = current_session.query(AccessPrivilege).filter(
        AccessPrivilege.project_id == proj.id
    )
    users_to_remove = []
    for access in accesses:
        num = (
            current_session.query(func.count(AccessPrivilege.project_id))
            .filter(AccessPrivilege.user_id == access.user_id)
            .scalar()
        )
        if num == 1:
            for storage in storage_access:
                provider = (
                    current_session.query(CloudProvider)
                    .filter(CloudProvider.id == storage.provider_id)
                    .first()
                )
                usr = (
                    current_session.query(User)
                    .filter(User.id == access.user_id)
                    .first()
                )
                users_to_remove.append((provider, usr))
                current_session.delete(usr)
        current_session.delete(access)
    for storage in storage_access:
        current_session.delete(storage)
    current_session.delete(proj)
    return {"result": "success", "users_to_remove": users_to_remove}


def delete_bucket_on_project(current_session, project_name, bucket_name):
    """
    Remove a bucket and its relationship to a project
    """
    bucket = current_session.query(Bucket).filter_by(name=bucket_name).first()
    if not bucket:
        msg = "".join(["Bucket name ", bucket_name, " not found"])
        raise NotFound(msg)
    provider = (
        current_session.query(CloudProvider)
        .filter(CloudProvider.id == bucket.provider_id)
        .first()
    )
    project = (
        current_session.query(Project).filter(Project.name == project_name).first()
    )
    if not project:
        msg = "".join(["Project name ", project_name, " not found"])
        raise NotFound(msg)
    proj_to_bucket = (
        current_session.query(ProjectToBucket)
        .filter(
            ProjectToBucket.bucket_id == bucket.id,
            ProjectToBucket.project_id == project.id,
        )
        .first()
    )
    if proj_to_bucket:
        current_session.delete(proj_to_bucket)
        current_session.delete(bucket)
        return {"result": "success", "provider": provider}
    else:
        current_session.delete(bucket)
        msg = (
            "WARNING: Project-to-bucket "
            "relationship not found, deleting bucket anyway"
        )
        return {"result": msg, "provider": provider}


def list_buckets_on_project(current_session, project_name):
    """
    List all the buckets assigned to a project
    """
    project = (
        current_session.query(Project).filter(Project.name == project_name).first()
    )
    if not project:
        msg = "".join(["Project name ", project_name, " not found"])
        raise NotFound(msg)
    buckets = current_session.query(ProjectToBucket).filter(
        ProjectToBucket.project_id == project.id
    )
    response = {"buckets": []}
    for bucket in buckets:
        buck = (
            current_session.query(Bucket).filter(Bucket.id == bucket.bucket_id).first()
        )
        provider = (
            current_session.query(CloudProvider)
            .filter(CloudProvider.id == buck.provider_id)
            .first()
        )
        new_buck = {"name": buck.name, "provider": provider.name}
        response["buckets"].append(new_buck)
    return response


def get_cloud_providers_from_project(current_session, project_id):
    """
    Retrieve cloud provider to be used in other operations that require the
    backend.
    """
    accesses = current_session.query(StorageAccess).filter(
        StorageAccess.project_id == project_id
    )
    cloud_providers = []
    for access in accesses:
        cloud_providers.append(
            current_session.query(CloudProvider)
            .filter(CloudProvider.id == access.provider_id)
            .first()
        )
    return cloud_providers


def get_buckets_by_project_cloud_provider(current_session, prjct_id, provider_id):
    """
    List all the buckets assigned to a project
    """
    buckets = current_session.query(ProjectToBucket).filter_by(project_id=prjct_id)
    response = {"buckets": []}
    for bucket in buckets:
        buck = (
            current_session.query(Bucket)
            .filter(Bucket.id == bucket.bucket_id, Bucket.provider_id == provider_id)
            .first()
        )
        if buck:
            response["buckets"].append(buck)
    return response


def get_user_project_access_privilege(current_session, user, project):
    return (
        current_session.query(AccessPrivilege)
        .filter_by(project_id=project.id, user_id=user.id)
        .first()
    )
