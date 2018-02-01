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
    Group,
    UserToGroup,
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


def get_project_by_name(current_session, project_name):
    """
    Get project info from userdatamodel
    from its name
    """
    proj = current_session.query(
        Project).filter(Project.name == project_name).first()
    if not proj:
        msg = ''.join(['Error: project ', project_name, ' not found'])
        raise NotFound(msg)
    info = {
        'id': proj.id,
        'name': proj.name,
        'auth_id': proj.auth_id,
        'description': proj.description,
        'associated buckets': []
    }
    buckets = current_session.query(
        ProjectToBucket).filter(ProjectToBucket.project_id == proj.id)
    for row in buckets:
        bucket = current_session.query(
            Bucket).filter(Bucket.id == row.bucket_id).first()
        info['associated buckets'].append(bucket.name)
    return info

def delete_project_by_name(current_session, project_name):
    """
    Delete the project from the database
    The project should have no buckets in use
    """
    proj = current_session.query(
        Project).filter(Project.name == project_name).first()
    if proj:
        buckets = current_session.query(
            ProjectToBucket).filter(
                ProjectToBucket.project_id == proj.id).first()
        if not buckets:
            storage_access = current_session.query(
                StorageAccess).filter(
                    StorageAccess.project_id == proj.id)
            """
            Find the users that only belong to this project
            and store them to be removed
            """
            accesses = current_session.query(
                AccessPrivilege).filter(
                    AccessPrivilege.project_id == proj.id)
            users_to_remove = []            
            for access in accesses:
                num = current_session.query(
                    func.count(
                        AccessPrivilege.project_id)).filter(
                            AccessPrivilege.user_id == access.user_id).scalar()
                if num == 1:
                    for storage in storage_access:
                        provider = current_session.query(
                            CloudProvider).filter(
                                CloudProvider.id == storage.provider_id).first()
                        usr = current_session.query(
                            User).filter(User.id == access.user_id).first()
                        users_to_remove.append((provider,usr))
                        current_session.delete(usr)
                current_session.delete(access)
            for storage in storage_access:
                current_session.delete(storage)
            current_session.delete(proj)
            return {"result": "success", "users_to_remove": users_to_remove}
        else:
            msg = ("error, project still has buckets"
                   " associated with it. Please remove"
                   " those first and then retry.")
            return {"result": msg}
    else:
        return {"result": "error, project not found"}

def get_provider_by_name(current_session, provider_name):
    """
    Get the provider info from the userdatamodel
    """
    provider = current_session.query(
        CloudProvider).filter(CloudProvider.name == provider_name).first()
    if not provider:
        msg = "".join(["error, cloud provider ", provider_name, " not found"])
        raise NotFound(msg)
    info = {
        'name': provider.name,
        'backend': provider.backend,
        'endpoint': provider.endpoint,
        'description': provider.description,
        'service': provider.service
    }
    return info

def delete_provider_by_name(current_session, provider_name):
    """
    Delete a cloud provider if it has not
    ongoing relationships
    """
    provider = current_session.query(
        CloudProvider).filter(CloudProvider.name == provider_name).first()
    if provider:
        projects = current_session.query(
            StorageAccess).filter(
                StorageAccess.provider_id == provider.id).first()
        if projects:
            msg = "".join(
                ["provider name ",
                 provider_name,
                 (" in use in projects."
                  " Please remove these references and retry")])
            raise UserError(msg)
        else:
            current_session.delete(provider)
            return {"response": "success"}
    else:
        msg = "".join(["provider name ", provider_name, " not found"])
        raise NotFound(msg)

def delete_user_by_username(current_session, username):
    """
    Delete the user with the given username
    """
    user = current_session.query(
        User).filter(User.username == username).first()
    if user:
        accesses = current_session.query(
            AccessPrivilege).filter(AccessPrivilege.user_id == user.id)
        cloud_providers = []
        for row in accesses:
            proj = current_session.query(
                StorageAccess).filter(
                    StorageAccess.project_id == row.project_id).first()
            cloud_providers.append(
                current_session.query(
                    CloudProvider).filter(
                        CloudProvider.id == proj.provider_id).first())
            current_session.delete(row)
        current_session.delete(user)
        return {"result": "success", "providers": cloud_providers, "user": user}
    else:
        msg = "".join(["user name ", username, " not found"])
        raise NotFound(msg)


def delete_bucket_on_project_by_name(current_session, project_name, bucket_name):
    """
    Remove a bucket and its relationship to a project
    """
    bucket = current_session.query(
        Bucket).filter(Bucket.name == bucket_name).first()
    if not bucket:
        msg = "".join(["Bucket name ", bucket_name, " not found"])
        raise NotFound(msg)
    provider = current_session.query(
        CloudProvider).filter(
            CloudProvider.id == bucket.provider_id).first()
    project = current_session.query(
        Project).filter(Project.name == project_name).first()
    if not project:
        msg = "".join(["Project name ", project_name, " not found"])
        raise NotFound(msg)
    proj_to_bucket = current_session.query(
        ProjectToBucket).filter(
            ProjectToBucket.bucket_id == bucket.id ,
            ProjectToBucket.project_id == project.id).first()
    if proj_to_bucket:
        current_session.delete(proj_to_bucket)
        current_session.delete(bucket)
        return {"result": "success", "provider": provider}
    else:
        current_session.delete(bucket)
        current_session.flush()
        msg = ("WARNING: Project-to-bucket "
               "relationship not found, deleting bucket anyway")
        return  {"result": msg, "provider": provider}

def list_buckets_on_project_by_name(current_session, project_name):
    """
    List all the buckets assigned to a project
    """
    project = current_session.query(
        Project).filter(Project.name == project_name).first()
    if not project:
        msg = ''.join(["Project name ", project_name, " not found"])
        raise NotFound(msg)
    buckets = current_session.query(
        ProjectToBucket).filter(ProjectToBucket.project_id == project.id)
    response = {"buckets": []}
    for bucket in buckets:
        buck = current_session.query(
            Bucket).filter(Bucket.id == bucket.bucket_id).first()
        provider = current_session.query(
            CloudProvider).filter(CloudProvider.id == buck.provider_id).first()
        new_buck = {
            "name": buck.name,
            "provider": provider.name
            }
        response['buckets'].append(new_buck)
    return response

def get_cloud_providers_from_project(current_session, project_id):
    """
    Retrieve cloud provider to be used in other
    operations that require the backend
    """
    accesses = current_session.query(StorageAccess).filter(
        StorageAccess.project_id == project_id)
    cloud_providers = []
    for access in accesses:
        cloud_providers.append(
            current_session.query(CloudProvider).filter(
                CloudProvider.id == access.provider_id).first())
    return cloud_providers

def create_user_by_username_project(current_session, new_user, proj):
    """
    Create a user for a specific project
    """
    project = current_session.query(Project).filter(
        Project.auth_id == proj['auth_id']).first()
    if not project:
        msg = "".join(
            ["error: auth_id name ",
             proj['auth_id'],
             " not found"]
        )
        raise NotFound(msg)

    #If am enforcing a full match.
    #The table has keys that only comprehend two of the arguments
    #I will address that option later.
    #For now, we need a full match to replace or update
    priv = current_session.query(AccessPrivilege).filter(
        AccessPrivilege.user_id == new_user.id,
        AccessPrivilege.project_id == project.id).first()
    if priv:
        #I update the only updatable field
        priv.privilege = proj['privilege']
    else:
        priv = AccessPrivilege(
            user_id=new_user.id,
            project_id=project.id,
            privilege=proj['privilege']
        )
        current_session.add(priv)
        current_session.flush()

    return {"user": new_user,
            "result": "success",
            "project": project,
            "privileges": priv}

def get_buckets_by_project_cloud_provider(current_session, project_id, provider_id):
    """
    List all the buckets assigned to a project
    """
    buckets = current_session.query(ProjectToBucket).filter(
        ProjectToBucket.project_id == project_id)
    response = {"buckets": []}
    for bucket in buckets:
        buck = current_session.query(Bucket).filter(
            Bucket.id == bucket.bucket_id,
            Bucket.provider_id == provider_id).first()
        if buck:
            response['buckets'].append(buck)
    return response

def create_group(groupname, lead):
    group = current_session.query(Group).filter(
        Group.name == groupname).first()
    if group:
        raise UserError("Group already exists")
    else:
        group = Group()
        group.name = groupname
        group.lead_id = lead
        current_session.add(group)
        current_session.flush()
        return {'result': "success"}

def delete_group(groupname):
    group = current_session.query(Group).filter(
        Group.name == groupname).first()
    if not group:
        raise UserError("Group doesn't exist")
    else:
        current_session.delete(group)
        current_session.flush()


def clear_projects_in_group(groupname):
    group = current_session.query(Group).filter(
        Group.name == groupname).first()
    if group:
        links = current_session.query(AccessPrivilege).filter(
            AccessPrivilege.group_id == group.id)
        for link in links:
            current_session.delete(link)
            current_session.flush()

def clear_users_in_group(groupname):
    group = current_session.query(Group).filter(
        Group.name == groupname).first()
    if group:
        links = current_session.query(UserToGroup).filter(
            UserToGroup.group_id == group.id)
        for link in links:
            current_session.delete(link)
            current_session.flush()
