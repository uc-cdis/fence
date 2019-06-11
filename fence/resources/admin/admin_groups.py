from fence.resources.admin import admin_users as au
from fence.errors import NotFound, UserError
from fence.resources import group as gp, project as pj, user as us


__all__ = [
    "create_group",
    "delete_group",
    "update_group",
    "get_group_info",
    "get_all_groups",
    "get_group_users",
    "connect_project_to_group",
    "update_group_users_projects",
    "add_projects_to_group",
    "disconnect_project_from_group",
    "update_user_projects_within_group",
    "remove_projects_from_group",
    "get_group_projects",
]


def create_group(current_session, groupname, description):
    """
    Creates a group and returns it
    """
    return gp.create_group(current_session, groupname, description)


def delete_group(current_session, groupname):
    """
    Deletes a group
    """
    projects_to_purge = gp.get_group_projects(current_session, groupname)
    remove_projects_from_group(current_session, groupname, projects_to_purge)
    gp.clear_users_in_group(current_session, groupname)
    gp.clear_projects_in_group(current_session, groupname)
    gp.delete_group(current_session, groupname)
    return {"result": "success"}


def update_group(current_session, groupname, description, new_name=None):
    gp.update_group(current_session, groupname, description, new_name)
    name = new_name or groupname
    return gp.get_group_info(current_session, name)


def get_group_info(current_session, groupname):
    return gp.get_group_info(current_session, groupname)


def get_all_groups(current_session):
    groups = gp.get_all_groups(current_session)
    groups_list = [get_group_info(current_session, group.name) for group in groups]
    return {"groups": groups_list}


def get_group_users(current_session, groupname):
    users = gp.get_group_users(current_session, groupname)
    get_user_info = lambda user: us.get_user_info(current_session, user.username)
    users_names = [
        {"name": the_user["name"], "role": the_user["role"]}
        for the_user in map(get_user_info, users)
    ]
    return {"users": users_names}


def connect_project_to_group(current_session, grp, project=None):
    prj = pj.get_project(current_session, project)
    if not prj:
        raise UserError(("Project {0} doesn't exist".format(project)))
    return gp.connect_project_to_group(current_session, grp, prj)


def update_group_users_projects(current_session, group, project, users):
    proj = pj.get_project(current_session, project)
    for user in users:
        try:
            user_projects = list(user.project_access.keys())
            if project not in user_projects:
                project_info = {"auth_id": proj.auth_id, "privilege": ["read"]}
                au.connect_user_to_project(
                    current_session,
                    us.get_user(current_session, user.username),
                    project_info,
                )
        except NotFound:
            pass
    return {
        "success": "users {0} connected to project {1}".format(
            [user.username for user in users], project
        )
    }


def add_projects_to_group(current_session, groupname, projects=None):
    if not projects:
        projects = []
    grp = gp.get_group(current_session, groupname)
    usrs = gp.get_group_users(current_session, groupname)
    if not grp:
        raise UserError("Error: group does not exist")
    responses = []
    for proj in projects:
        try:
            response = connect_project_to_group(current_session, grp, proj)
            responses.append(response)
            update_group_users_projects(current_session, grp, proj, usrs)
        except Exception as e:
            current_session.rollback()
            raise e
    return {"result": responses}


def disconnect_project_from_group(current_session, grp, projectname):
    prj = pj.get_project(current_session, projectname)
    if not prj:
        return {"warning": ("Project {0} doesn't exist".format(projectname))}
    return gp.remove_project_from_group(current_session, grp, prj)


def update_user_projects_within_group(
    current_session, username, groupname, projectname
):
    user_groups = us.get_user_groups(current_session, username)
    """
    Simplified version for awg:
      Users only have read permission, so just checking the
      presence of the project in any of their other groups
      suffices to keep the projec in the list.
    In real life we should check permissions coming from all groups
    and remove the specific ones comiing from groupname
    """
    group_projects = [
        gp.get_group_projects(current_session, group)
        for group in user_groups["groups"]
        if group != groupname
    ]

    projects_to_keep = [item for sublist in group_projects for item in sublist]

    if projectname not in projects_to_keep:
        try:
            us.remove_user_from_project(
                current_session,
                us.get_user(current_session, username),
                pj.get_project(current_session, projectname),
            )
        except NotFound:
            # somehow the user was not linked to that project
            pass


def remove_projects_from_group(current_session, groupname, projects=None):
    if not projects:
        projects = []
    grp = gp.get_group(current_session, groupname)
    usrs = get_group_users(current_session, groupname)
    users_names = [x["name"] for x in usrs["users"]]
    if not grp:
        raise UserError("Error: group does not exist")
    responses = []
    for proj in projects:
        for usr in users_names:
            update_user_projects_within_group(current_session, usr, groupname, proj)
        response = disconnect_project_from_group(current_session, grp, proj)
        responses.append(response)
    return {"result": responses}


def get_group_projects(current_session, groupname):
    return gp.get_group_projects(current_session, groupname)
