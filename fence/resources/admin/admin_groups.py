from fence.resources import (
    userdatamodel as udm,
    project as pj,
    group as gp,
    user as us,
    provider as pv
)

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
        groups_list.append(group.name)
    return {"groups": groups_list}


def get_group_users(current_session, groupname):
    users = gp.get_group_users(current_session, groupname)
    users_names = []
    for user in users:
        users_names.append(user.username)
    return {"users": users_names}


def connect_project_to_group(current_session, grp, project=None):
    prj = pj.get_project(current_session, project)
    if not prj:
        raise UserError(("Project {0} doesn't exist".format(project)))
    else:
        return udm.connect_project_to_group(current_session, grp, prj)


def update_group_users_projects(current_session, group, project, users):
    for user in users:
        pass


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
    

def remove_projects_from_group(current_session, groupname, projects=[]):
    grp = gp.get_group(current_session, groupname)
    if not grp:
        raise UserError ("Error: group does not exist")
    else:
        responses = []
        for proj in projects:
            try:
                response = disconnect_project_from_group(current_session, grp, proj)
                responses.append(response)
            except Exception as e:
                current_session.rollback()
                raise e
        return {"result": responses}


def get_group_projects(current_session, groupname):
    return gp.get_group_projects(current_session, groupname)
