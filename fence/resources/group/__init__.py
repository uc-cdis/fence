from flask import current_app as capp

from fence.data_model.models import ResearchGroup
from fence.errors import NotFound

def find_group(group_id, session):
    """Query the DB for the group in question.

    Return ResearchGroup object, or throw an exception if no such group exists.
    """
    group = session.query(ResearchGroup).filter(ResearchGroup.id == group_id).first()
    if not group:
        raise NotFound("group {} not found".format(group_id))
    return group

def get_group_info(group):
    """Given a ResearchGroup object, returns a dict containing its fields."""
    info = {
        'group_id': group.id,
        'group_name': group.name,
        'lead_id': group.lead_id
    }
    return info

def get_info_by_group_id(group_id):
    with capp.db.session as session:
        return get_group_info(find_group(group_id, session))
