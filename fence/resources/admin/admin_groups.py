from fence.resources import (
    userdatamodel as udm,
    project as pj,
    group as gp,
    user as us,
    provider as pv
)

import admin_users as au
from flask import current_app as capp
from fence.data_model.models import User, Group
from fence.errors import NotFound
import json
from fence.errors import UserError



#### GROUPS ####


def create_group(current_session, groupname, description):
    """
    Creates a group and returns it
    """
    return gp.create_group(current_session, groupname, description)


def delete_group(current_session, groupname):
    """
    Deletes a group
    """
    projects_to_purge =  gp.get_group_projects(current_session,
                                              groupname)
    remove_projects_from_group(current_session, groupname,
                               projects_to_purge)
    gp.clear_users_in_group(current_session, groupname)
    gp.clear_projects_in_group(current_session, groupname)
    gp.delete_group(current_session, groupname)
    return {'result': 'success'}


def update_group(current_session, groupname, description):
    gp.update_group(current_session, groupname, description)
    return gp.get_group_info(current_session, groupname)


def get_group_info(current_session, groupname):
    return gp.get_group_info(current_session, groupname)


def get_all_groups(current_session):
    groups = gp.get_all_groups(current_session)
    groups_list = []
    for group in groups:
        groups_list.append(get_group_info(current_session, group.name))
    return {"groups": groups_list}


def get_group_users(current_session, groupname):
    users = gp.get_group_users(current_session, groupname)
    users_names = []
    for user in users:
        the_user = us.get_user_info(current_session, user.username)
        users_names.append({"name": the_user['username'], "role": the_user['role']})
    return {"users": users_names}


def connect_project_to_group(current_session, grp, project=None):
    prj = pj.get_project(current_session, project)
    if not prj:
        raise UserError(("Project {0} doesn't exist".format(project)))
    else:
        return udm.connect_project_to_group(current_session, grp, prj)


def update_group_users_projects(current_session, group, project, users):
    proj = pj.get_project(current_session, project)
    for user in users:
        try:
            user_projects = user.project_access.keys()
            if project not in user_projects:
                project_info = {"auth_id": proj.auth_id,
                                "privilege": ["read"]}
                au.connect_user_to_project(current_session,
                                           us.get_user(current_session,
                                                       user.username),
                                           project_info)
        except NotFound:
            pass
    return {"success": "users {0} connected to project {1}".format(
        users, project)}

def add_projects_to_group(current_session, groupname, projects=[]):
    grp = gp.get_group(current_session, groupname)
    usrs = gp.get_group_users(current_session, groupname)
    if not grp:
        raise UserError ("Error: group does not exist")
    else:
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
    else:
        return udm.remove_project_from_group(current_session, grp, prj)
    

def update_user_projects_within_group(current_session, username, groupname, projectname):
    user_groups = us.get_user_groups(current_session, username)
    # simplified version for awg
    # users only have read permission, so just checking the
    # presence of the project in any of their other groups
    # suffices to keep the projec in the list
    # In real life we should check permissions coming from all groups
    # and remove the specific ones comiing from groupname
    projects_to_keep = [ item for sublist in
                         [gp.get_group_projects(current_session, group)
                          for group in user_groups['groups']
                          if group != groupname ]
                         for item in sublist ]
    
    if projectname not in projects_to_keep:
        try:
            us.remove_user_from_project(current_session,
                                        us.get_user(current_session, username),
                                        pj.get_project(current_session, projectname))
        except NotFound() as e:
            # somehow the user was not linked to that project
            pass

def remove_projects_from_group(current_session, groupname, projects=[]):
    grp = gp.get_group(current_session, groupname)
    usrs = get_group_users(current_session, groupname)
    if not grp:
        raise UserError ("Error: group does not exist")
    else:
        responses = []
        try:
            for proj in projects:
                for usr in usrs['users']:
                    update_user_projects_within_group(current_session, usr, groupname, proj)
                response = disconnect_project_from_group(current_session, grp, proj)
                responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
        return {"result": responses}


def get_group_projects(current_session, groupname):
    return gp.get_group_projects(current_session, groupname)
