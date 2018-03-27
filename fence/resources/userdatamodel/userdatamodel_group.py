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

from fence.errors import (
    NotFound,
    UserError,
)


def clear_projects_in_group(current_session, groupname):
    group = current_session.query(Group).filter(
        Group.name == groupname).first()
    if group:
        links = current_session.query(AccessPrivilege).filter(
            AccessPrivilege.group_id == group.id)
        for link in links:
            current_session.delete(link)
            current_session.flush()

def clear_users_in_group(current_session, groupname):
    group = current_session.query(Group).filter(
        Group.name == groupname).first()
    if group:
        links = current_session.query(UserToGroup).filter(
            UserToGroup.group_id == group.id)
        for link in links:
            current_session.delete(link)
            current_session.flush()

def get_group(current_session, groupname):
    return current_session.query(Group).filter(
        Group.name == groupname).first()


def get_user_group_access_privilege(current_session, user, group):
    return current_session.query(UserToGroup).filter(
        UserToGroup.user_id == user.id).filter(
            UserToGroup.group_id == group.id).first()

def get_project_group_access_privilege(current_session, project, group):
    return current_session.query(AccessPrivilege).filter(
        AccessPrivilege.project_id == project.id).filter(
            AccessPrivilege.group_id == group.id).first()


def get_all_groups(current_session):
    return current_session.query(Group).all()

def get_group_users(current_session, groupname):
    group = get_group(current_session, groupname)
    user_to_groups = current_session.query(UserToGroup).filter(
        UserToGroup.group_id == group.id).all()
    users = []
    for user in user_to_groups:
        new_user = current_session.query(User).filter(
            User.id == user.user_id).first()
        if new_user:
            users.append(new_user)
    return users


def get_group_projects(current_session, groupname):
    group = get_group(current_session, groupname)
    if not group:
        raise NotFound("Group {0} does not exist".format(groupname))
    projects_to_group = current_session.query(AccessPrivilege).filter(
        AccessPrivilege.group_id == group.id).all()
    projects = []
    for project in projects_to_group:
        new_project = current_session.query(Project).filter(
            Project.id == project.project_id).first()
        if new_project:
            projects.append(new_project.name)
    return projects


def get_empty_group():
    return Group()


def get_user_to_group():
    return UserToGroup()


def get_project_to_group():
    return AccessPrivilege()
