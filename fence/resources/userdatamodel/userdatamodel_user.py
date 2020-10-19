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
    query_for_user,
)


__all__ = [
    "get_user",
    "get_user_accesses",
    "create_user_by_username_project",
    "get_all_users",
    "get_user_groups",
    "update_user",
]


def get_user(current_session, username):
    return query_for_user(session=current_session, username=username)

def update_user(current_session, username, additional_info):
    return (
        current_session.query(User).filter(User.username == username).update({User.additional_info: additional_info})
    )

def get_user_accesses(current_session):
    return (
        current_session.query(User).join(User.groups).filter(User.id == flask.g.user.id)
    )


def create_user_by_username_project(current_session, new_user, proj):
    """
    Create a user for a specific project
    """
    project = (
        current_session.query(Project)
        .filter(Project.auth_id == proj["auth_id"])
        .first()
    )
    if not project:
        msg = "".join(["error: auth_id name ", proj["auth_id"], " not found"])
        raise NotFound(msg)

    # If am enforcing a full match.
    # The table has keys that only comprehend two of the arguments
    # I will address that option later.
    # For now, we need a full match to replace or update
    priv = (
        current_session.query(AccessPrivilege)
        .filter(
            AccessPrivilege.user_id == new_user.id,
            AccessPrivilege.project_id == project.id,
        )
        .first()
    )
    if priv:
        # I update the only updatable field
        priv.privilege = proj["privilege"]
    else:
        priv = AccessPrivilege(
            user_id=new_user.id, project_id=project.id, privilege=proj["privilege"]
        )
        current_session.add(priv)
        current_session.flush()

    return {"user": new_user, "project": project, "privileges": priv}


def get_all_users(current_session):
    return current_session.query(User).all()


def get_user_groups(current_session, username):
    user = get_user(current_session, username)
    groups_to_list = current_session.query(UserToGroup).filter(
        UserToGroup.user_id == user.id
    )
    groups = []
    for group in groups_to_list:
        group_to_retrieve = (
            current_session.query(Group).filter(Group.id == group.group_id).first()
        )
        groups.append(group_to_retrieve.name)
    return {"groups": groups}
