import flask
from sqlalchemy import func, or_

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
from fence.pagination import paginate

__all__ = [
    "get_user",
    "get_user_accesses",
    "create_user_by_username_project",
    "get_all_users",
    "get_paginated_users",
    "get_user_groups",
]


def get_user(current_session, username):
    return query_for_user(session=current_session, username=username)


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


def _get_user_query(current_session, keyword=None):
    q = current_session.query(User)
    if keyword:
        keyword = keyword.replace(' ', '').lower()
        q = q.filter(
            or_(
                func.replace(User.display_name, ' ', '').ilike(
                    '%{}%'.format(keyword)),
                func.replace(User.email, ' ', '').ilike(
                    '%{}%'.format(keyword)),
            )
        )
    return q


def get_all_users(current_session, keyword=None):
    q = _get_user_query(current_session, keyword)
    return q.order_by(User.id.desc()).all()


def get_paginated_users(current_session, page, page_size, keyword=None):
    q = _get_user_query(current_session, keyword)
    q = q.order_by(User.id.desc())
    page = int(page)
    page_size = int(page_size)
    pagination = paginate(
        query=q,
        page=page,
        per_page=page_size,
        error_out=False
    )
    return pagination


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
