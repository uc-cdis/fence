from fence.errors import NotFound, UserError
from fence.models import User
from fence.resources import (
    group as gp,
    project as pj,
    user as us,
    userdatamodel as udm
)
from flask import current_app as capp


__all__ = [
    'connect_user_to_project', 'get_user_info', 'get_all_users',
    'get_user_groups', 'create_user', 'update_user', 'add_user_to_projects',
    'delete_user', 'add_user_to_groups', 'connect_user_to_group',
    'remove_user_from_groups', 'disconnect_user_from_group',
    'remove_user_from_project'
]


def connect_user_to_project(current_session, usr, project=None):
    """
    Create a user name for the specific project.
    Returns a dictionary.
    """
    datamodel_user = udm.create_user_by_username_project(
        current_session,
        usr,
        project
    )

    proj = datamodel_user["project"]
    priv = datamodel_user["privileges"]
    cloud_providers = udm.get_cloud_providers_from_project(current_session, proj.id)
    response = []
    for provider in cloud_providers:
        capp.storage_manager.get_or_create_user(provider.backend, usr)
        buckets = udm.get_buckets_by_project_cloud_provider(
            current_session, proj.id, provider.id)
        for bucket in buckets["buckets"]:
            try:
                capp.storage_manager.update_bucket_acl(
                    provider.backend,
                    bucket,
                    (usr, priv.privilege))
                msg = ("Success: user access"
                       " created for a bucket in the project {0}")
                response.append(msg.format(proj.name))
            except:
                msg = ("Error user access not"
                       " created for project {0} and bucket {2}")
                response.append(
                    msg.format(proj.name, bucket["name"]))
    return response


def get_user_info(current_session, username):
    return us.get_user_info(current_session, username)


def get_all_users(current_session):
    users = udm.get_all_users(current_session)
    users_names = []
    for user in users:
        new_user = {}
        new_user['name'] = user.username
        if user.is_admin:
            new_user['role'] = "admin"
        else:
            new_user['role'] = "user"
        users_names.append(new_user)
    return {"users": users_names}


def get_user_groups(current_session, username):
    user_groups = us.get_user_groups(current_session, username)['groups']
    user_groups_info = []
    for group in user_groups:
        user_groups_info.append(gp.get_group_info(current_session, group))
    return {"groups": user_groups_info}


def create_user(current_session, username, role, email):
    """
    Create a user for all the projects or groups in the list.
    If the user already exists, to avoid unadvertedly changing it, we suggest update
    Returns a dictionary.
    """
    try:
        usr = us.get_user(current_session, username)
        raise UserError(("Error: user already exist. If this is not a"
               " mistake, please, retry using update"))
        return msg
    except NotFound:
        user_list = [user['name'].upper() for user in get_all_users(current_session)['users']]
        if username.upper() in user_list:
            raise UserError(("Error: user with a name with the same combination/order "
                             "of characters already exists. Please remove this other user"
                             " or modify the new one. Contact us in case of doubt"))
        is_admin = role == "admin"
        email_add = email
        usr = User(username=username, active=True, is_admin=is_admin, email=email_add)
        current_session.add(usr)
        return us.get_user_info(current_session, username)


def update_user(current_session, username, role, email, new_name):
    usr = us.get_user(current_session, username)
    user_list = [user['name'].upper() for user in get_all_users(current_session)['users']]
    if new_name.upper() in user_list and not username.upper() == new_name.upper():
        raise UserError(("Error: user with a name with the same combination/order "
                         "of characters already exists. Please remove this other user"
                         " or modify the new one. Contact us in case of doubt"))
    usr.email = email or usr.email
    if role:
        is_admin = True if role == 'admin' else False
    else:
        is_admin = usr.is_admin
    usr.is_admin = is_admin
    usr.username = new_name or usr.username
    return us.get_user_info(current_session, usr.username)


def add_user_to_projects(current_session, username, projects=None):
    if not projects:
        projects = []
    usr = us.get_user(current_session, username)
    responses = []
    for proj in projects:
        try:
            response = connect_user_to_project(current_session, usr, proj)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    return {"result": responses}


def delete_user(current_session, username):
    """
    Remove a user from both the userdatamodel
    and the assciated storage for that project/bucket.
    Returns a dictionary.
    """
    response = us.delete_user(current_session, username)
    if response["result"] == "success":
        providers = response.get("providers",[])
        for provider in providers:
            capp.storage_manager.delete_user(provider.backend, response["user"])
        
        return {"result": "success"}


def add_user_to_groups(current_session, username, groups=None):
    if not groups:
        groups = []
    usr = us.get_user(current_session, username)
    responses = []
    for groupname in groups:
        try:
            response = connect_user_to_group(current_session, usr, groupname)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    return {"result": responses}


def connect_user_to_group(current_session, usr, groupname=None):
    grp = gp.get_group(current_session, groupname)
    if not grp:
        raise UserError(("Group {0} doesn't exist".format(groupname)))
    else:
        responses = []
        responses.append(gp.connect_user_to_group(current_session, usr, grp))
        projects = gp.get_group_projects(current_session, groupname)
        projects_data = [ pj.get_project(current_session, project).auth_id for project in projects]
        projects_list = [{"auth_id": auth_id, "privilege": ["read"]} for auth_id in projects_data]
        for project in projects_list:
            connect_user_to_project(current_session, usr, project)
        return responses


def remove_user_from_groups(current_session, username, groups=None):
    if not groups:
        groups = []
    usr = us.get_user(current_session, username)
    user_groups = us.get_user_groups(current_session, username)['groups']
    groups_to_keep =  [x for x in user_groups if x not in groups]

    projects_to_keep =  {item for sublist in
                          [gp.get_group_projects(current_session, x) for x in groups_to_keep]
                          for item in sublist}

    projects_to_remove = {item for sublist in
                          [ gp.get_group_projects(current_session, x) for x in groups]
                          for item in sublist if item not in projects_to_keep}

    responses = []
    for groupname in groups:
        try:
            response = disconnect_user_from_group(current_session, usr, groupname)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    for project in projects_to_remove:
        remove_user_from_project(current_session, usr, project)
    return {"result": responses}


def disconnect_user_from_group(current_session, usr, groupname):
    grp = gp.get_group(current_session, groupname)
    if not grp:
        return {"warning": ("Group {0} doesn't exist".format(group))}

    response = gp.remove_user_from_group(current_session, usr, grp)
    projects = gp.get_group_projects(current_session, groupname)
    projects_data = [
        pj.get_project(current_session, project).auth_id
        for project in projects
    ]
    return response


def remove_user_from_project(current_session, usr, project_name):
    proj = pj.get_project(current_session, project_name)
    us.remove_user_from_project(current_session, usr, proj)
