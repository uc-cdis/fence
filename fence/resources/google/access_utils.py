from cirrus import GoogleCloudManager

ALLOWED_SERVICE_ACCOUNT_TYPES = [
    "COMPUTE_ENGINE_DEFAULT",
    "USER_MANAGED",
]


def is_valid_service_account_type(project_id, account_id):

    try:
        with GoogleCloudManager(project_id) as g_mgr:
            return g_mgr.get_service_account_type(account_id) in ALLOWED_SERVICE_ACCOUNT_TYPES
    except:
        return False

