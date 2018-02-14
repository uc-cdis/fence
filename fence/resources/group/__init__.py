from fence.resources import userdatamodel as udm

def get_group(current_session, groupname):
    return udm.get_group(current_session, groupname)

def clear_users_in_group(current_session, groupname):
    return udm.clear_users_in_group(current_session, groupname)

def clear_projects_in_group(current_session, groupname):
    return udm.clear_projects_in_group(current_session, groupname)

def delete_group(current_session, groupname):
    return udm.delete_group(current_session, groupname)

def create_group(current_session, groupname, description):
    return udm.create_group(current_session, groupname, description)

def get_group_users(current_session, groupname):
    return udm.get_group_users(current_session, groupname)

def get_all_groups(current_session):
    return udm.get_all_groups(current_session)

def get_group_projects(current_session, groupname):
    return udm.get_group_projects(current_session, groupname)

    
