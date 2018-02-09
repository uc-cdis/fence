import fence.resources.userdatamodel as udm

def get_project(current_session, project_name):
    return udm.get_project(current_session, project_name)

def get_project_info(current_session, project_name):
    return udm.get_project_info(current_session, project_name)

def create_project(current_session, projectname, authid, storageaccesses):
    return udm.create_project(current_session, projectname, authid, storageaccesses)

def delete_project(current_session, project_name):
    return udm.delete_project(current_session, project_name)

def create_bucket_on_project(current_session, project_name, bucket_name, provider_name):
    return udm.create_bucket_on_project(current_session,
                                                project_name, bucket_name, provider_name)

def delete_bucket_on_project(current_session, project_name, bucket_name):
    return udm.delete_bucket_on_project(current_session, project_name, bucket_name)

def list_buckets_on_project(current_session, project_name):
    return udm.list_buckets_on_project(current_session, project_name)
