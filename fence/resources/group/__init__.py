from flask import current_app as capp
from flask import jsonify, g

from fence.data_model.models import ResearchGroup

def find_group(group_id, session):
    group = session.query(ResearchGroup).filter(ResearchGroup.id == group_id).first()
    if not group:
        raise NotFound("group {} not found".format(group_id))
    return group

def get_group_info(group, session):
    info = {
        'group_id': group.id,
        'group_name': group.name,
        'lead_id': group.lead_id
    }
    return jsonify(info)

def get_info_by_group_id(group_id):
    with capp.db.session as session:
        return get_group_info(find_group(group_id, session), session)
