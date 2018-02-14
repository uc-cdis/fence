from fence.resources import userdatamodel as udm

def get_provider(current_session, provider_name):
    return udm.get_provider(current_session, provider_name)

def create_provider(current_session, provider_name,
                    backend, service, endpoint, description):
    return udm.create_provider(current_session, provider_name,
                               backend, service, endpoint,
                               description)
