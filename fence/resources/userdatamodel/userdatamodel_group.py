from fence.models import Project, User, AccessPrivilege, Group, UserToGroup

__all__ = [
    "clear_projects_in_group",
    "clear_users_in_group",
    "get_group",
    "get_user_group_access_privilege",
    "get_project_group_access_privilege",
    "get_all_groups",
    "get_group_users",
    "get_group_projects",
    "get_empty_group",
    "get_user_to_group",
    "get_project_to_group",
]


def clear_projects_in_group(current_session, groupname):
    group = current_session.query(Group).filter(Group.name == groupname).first()
    if group:
        links = current_session.query(AccessPrivilege).filter(
            AccessPrivilege.group_id == group.id
        )
        for link in links:
            current_session.delete(link)


def clear_users_in_group(current_session, groupname):
    group = current_session.query(Group).filter(Group.name == groupname).first()
    if group:
        links = current_session.query(UserToGroup).filter(
            UserToGroup.group_id == group.id
        )
        for link in links:
            current_session.delete(link)


def get_group(current_session, groupname):
    return current_session.query(Group).filter_by(name=groupname).first()


def get_user_group_access_privilege(current_session, user, group):
    return (
        current_session.query(UserToGroup)
        .filter_by(user_id=user.id, group_id=group.id)
        .first()
    )


def get_project_group_access_privilege(current_session, project, group):
    return (
        current_session.query(AccessPrivilege)
        .filter_by(project_id=project.id, group_id=group.id)
        .first()
    )


def get_all_groups(current_session):
    return current_session.query(Group).all()


def get_group_users(current_session, group):
    user_to_groups = (
        current_session.query(UserToGroup)
        .filter(UserToGroup.group_id == group.id)
        .all()
    )
    users = []
    for user in user_to_groups:
        new_user = current_session.query(User).filter(User.id == user.user_id).first()
        if new_user:
            users.append(new_user)
    return users


def get_group_projects(current_session, group):
    projects_to_group = (
        current_session.query(AccessPrivilege)
        .filter(AccessPrivilege.group_id == group.id)
        .all()
    )
    projects = []
    for project in projects_to_group:
        new_project = (
            current_session.query(Project)
            .filter(Project.id == project.project_id)
            .first()
        )
        if new_project:
            projects.append(new_project.name)
    return projects


def get_empty_group():
    return Group()


def get_user_to_group():
    return UserToGroup()


def get_project_to_group():
    return AccessPrivilege()
