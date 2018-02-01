"""
Handle the group
"""
from flask_sqlalchemy_session import current_session as session
from flask import jsonify, g
from fence.data_model.models import ResearchGroup, AccessPrivilege


def get_group_by_name(group_name):
    """
    Get ReaserchGroup by group_name:
        - id
        - name
        - lead_id
    :param group_name: group name
    :return:
    """

    group_info = dict()

    group = session.query(ResearchGroup).filter(ResearchGroup.name == group_name).first()

    if group is not None:
        group_info["group_name"] = group.name

    return jsonify(group_info)


def get_all_groups_info():
    """
    Get all group information
    :return: a list of all groups
    """

    all_info = list()

    groups = session.query(ResearchGroup).all()

    for group in groups:
        print group
        all_info.append({'group_name': group.name})

    return jsonify({"result": all_info})


def get_projects_by_group(group_name):
    """
    Get all project info (project_id, privilege) associated with a group_name
    :param group_name:
    :return: List of projects
    """

    projects = list()

    group = session.query(ResearchGroup).filter(ResearchGroup.name == group_name).first()

    if group is not None:
        access_privileges = session.query(AccessPrivilege).\
            filter(AccessPrivilege.group_id == group.id).all()

        for access_privilege in access_privileges:
            projects.append({
                "project_id": access_privilege.project_id,
                "privilege": access_privilege.privilege
            })

    return jsonify({"result": projects})
