from fence.errors import (
    NotFound,
    UserError,
)
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
    'get_user', 'get_user_accesses', 'delete_user',
    'create_user_by_username_project', 'get_all_users', 'get_user_groups'
]


def get_user(current_session, username):
    return  current_session.query(User).filter(User.username == username).first()


def get_user_accesses(current_session):
    return  (
        current_session.query(User)
        .join(User.groups)
        .filter(User.id == flask.g.user.id)
    )


def delete_user(current_session, username):
    """
    Delete the user with the given username
    """
    user = current_session.query(
        User).filter(User.username == username).first()
    if not user:
        msg = "".join(["user name ", username, " not found"])
        raise NotFound(msg)

    accesses = current_session.query(
        AccessPrivilege).filter(AccessPrivilege.user_id == user.id)
    groups = current_session.query(
            UserToGroup).filter(
                UserToGroup.user_id == user.id).all()
    for row in groups:
        current_session.delete(row)

    cloud_providers = []
    for row in accesses:
        proj = current_session.query(
            StorageAccess).filter(
                StorageAccess.project_id == row.project_id).first()
        # commenting until we figure out why this is in ComputeQuota
        """
        cloud_providers.append(
            current_session.query(
                CloudProvider).filter(
                    CloudProvider.id == proj.provider_id).first())
        """
        current_session.delete(row)
    current_session.delete(user)
    return {"result": "success",
            #"providers": cloud_providers, 
            "user": user}
 

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
            "project": project,
            "privileges": priv}


def get_all_users(current_session):
    return current_session.query(User).all()


def get_user_groups(current_session, username):
    user = get_user(current_session, username)
    groups_to_list = current_session.query(UserToGroup).filter(
        UserToGroup.user_id == user.id)
    groups = []
    for group in groups_to_list:
        group_to_retrieve = current_session.query(Group).filter(
            Group.id == group.group_id).first()
        groups.append(group_to_retrieve.name)
    return {"groups" : groups}
