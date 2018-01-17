"""
Userdatamodel database operations.
These operations allow for the manipulation at
an administration level of the projects,
cloud providers and buckets on the database
"""
from flask_sqlalchemy_session import current_session
from sqlalchemy import func

from fence.data_model.models import (
    Project,
    StorageAccess,
    CloudProvider,
    ProjectToBucket,
    Bucket,
    User,
    AccessPrivilege,
)

from fence.errors import (
    NotFound,
    UserError,
)


def create_project_with_dict(current_session, project_data):
    """
    Create a project given a dict of all needed info
    Args:
        project_data (dict): dict of project info
    Return:
        None
    """
    auth_id = project_data['auth_id']
    name = project_data.get('name') or auth_id
    storage_accesses = project_data.get('storage_accesses', [])
    project = create_project(
        current_session, name, auth_id,
        [sa['name'] for sa in storage_accesses]
    )
    for sa in storage_accesses:
        for bucket in sa.get('buckets', []):
            create_bucket_on_project_by_name(
                current_session, name, bucket, sa['name'])

    return project

def create_project(
        current_session, name, auth_id, storage_accesses):
    """
    Creates a project with an associated auth_id and storage access
    """
    new_project = Project(name=name, auth_id=auth_id)
    current_session.add(new_project)
    current_session.flush()
    for storage in storage_accesses:
        provider = current_session.query(
            CloudProvider).filter(CloudProvider.name == storage).first()
        if provider:
            new_storage_access = StorageAccess(
                provider_id=provider.id, project_id=new_project.id)
            current_session.add(new_storage_access)
        else:
            raise NotFound('\n'.join(response))
    return new_project


def create_provider(
        current_session, provider_name,
        backend=None,
        service=None,
        endpoint=None,
        description=None):
    """
    Create a new provider on the table
    """
    check = current_session.query(
        CloudProvider).filter(CloudProvider.name == provider_name).first()
    if check:
        msg = "".join([
            "error, provider name ",
            provider_name,
            " already in use. Please, choose a different name and retry again"])
        raise UserError(msg)
    provider = CloudProvider(
        name=provider_name,
        backend=backend,
        service=service,
        endpoint=endpoint,
        description=description
    )
    current_session.add(provider)
    msg = {"result": "success"}
    return msg


def create_bucket_on_project_by_name(
        current_session, project_name, bucket_name, provider_name):
    """
    Create a bucket and assign it to a project
    """
    project = current_session.query(
        Project).filter(Project.name == project_name).first()
    if not project:
        msg = "".join(["Project ", project_name, " not found"])
        raise NotFound(msg)
    provider = current_session.query(
        CloudProvider).filter(CloudProvider.name == provider_name).first()
    if not provider:
        msg = "".join(["Provider ", provider_name, " not found"])
        raise NotFound(msg)
    bucket = current_session.query(
        Bucket).filter(Bucket.name == bucket_name,
                       Bucket.provider_id == provider.id).first()
    if not bucket:
        bucket = Bucket(name=bucket_name, provider_id=provider.id)
        current_session.add(bucket)
        current_session.flush()
        proj_to_bucket = ProjectToBucket(
            project_id=project.id, bucket_id=bucket.id, privilege=['owner'])
        current_session.add(proj_to_bucket)
        # Find the users that need to be deleted
        users_in_project = current_session.query(AccessPrivilege).filter(
            AccessPrivilege.project_id == project.id)
        users_to_update = []
        for row in users_in_project:
            usr = current_session.query(
                User).filter(User.id == row.user_id).first()
            users_to_update.append((usr, row.privilege))
        return {"result": "success", "provider": provider,
                "bucket": bucket, "users_to_update": users_to_update}
    else:
        raise UserError("Error, name already in use for that storage system")
