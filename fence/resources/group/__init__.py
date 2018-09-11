from fence.resources import userdatamodel as udm
from fence.errors import UserError, NotFound


def get_group(current_session, groupname):
    return udm.get_group(current_session, groupname)


def get_group_info(current_session, groupname):
    group = get_group(current_session, groupname)
    if not group:
        raise UserError("Error: group doesn't exist")

    projects = get_group_projects(current_session, groupname)
    return {"name": group.name, "description": group.description, "projects": projects}


def delete_group(current_session, groupname):
    group = udm.get_group(current_session, groupname)
    if not group:
        raise UserError("Group doesn't exist")
    else:
        current_session.delete(group)


def create_group(current_session, groupname, description):
    group = udm.get_group(current_session, groupname)
    if group:
        raise UserError("Group already exists")
    group = udm.get_empty_group()
    group.name = groupname
    group.description = description
    current_session.add(group)
    return {"result": "success"}


def update_group(current_session, groupname, description, new_name):
    group = get_group(current_session, groupname)
    group.description = description or group.description
    group.name = new_name or group.name


def connect_user_to_group(current_session, user, group):
    new_link = udm.get_user_to_group()
    new_link.user_id = user.id
    new_link.group_id = group.id
    current_session.add(new_link)
    return {
        "result": (
            "User: {0} SUCCESFULLY "
            "connected to Group: {1}".format(user.username, group.name)
        )
    }


def connect_project_to_group(current_session, group, project):
    new_link = udm.get_project_to_group()
    new_link.project_id = project.id
    new_link.group_id = group.id
    current_session.add(new_link)
    return {
        "result": (
            "Group: {0} SUCCESFULLY "
            "connected to Project: {1}".format(group.name, project.name)
        )
    }


def remove_user_from_group(current_session, user, group):
    to_be_removed = udm.get_user_group_access_privilege(current_session, user, group)
    if to_be_removed:
        current_session.delete(to_be_removed)
        return {
            "result": (
                "User: {0} SUCCESFULLY "
                "removed from Group: {1}".format(user.username, group.name)
            )
        }
    else:
        raise NotFound(
            "User {0} and Group {1} are not linked".format(user.username, group.name)
        )


def remove_project_from_group(current_session, group, project):
    to_be_removed = udm.get_project_group_access_privilege(
        current_session, project, group
    )
    if to_be_removed:
        current_session.delete(to_be_removed)
        msg = "Project: {0} SUCCESFULLY removed from Group: {1}".format(
            project.name, group.name
        )
        return {"result": msg}
    else:
        raise NotFound(
            "Project {0} and Group {1} are not linked".format(project.name, group.name)
        )


def get_group_users(current_session, groupname):
    group = get_group(current_session, groupname)
    return udm.get_group_users(current_session, group)


def get_all_groups(current_session):
    return udm.get_all_groups(current_session)


def get_group_projects(current_session, groupname):
    group = get_group(current_session, groupname)
    if not group:
        raise NotFound("Group {0} does not exist".format(groupname))
    return udm.get_group_projects(current_session, group)


def clear_users_in_group(current_session, groupname):
    return udm.clear_users_in_group(current_session, groupname)


def clear_projects_in_group(current_session, groupname):
    return udm.clear_projects_in_group(current_session, groupname)
