from cirrus import GoogleCloudManager
from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
)
ALLOWED_SERVICE_ACCOUNT_TYPES = [
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
]


def is_valid_service_account_type(project_id, account_id):

    try:
        with GoogleCloudManager(project_id) as g_mgr:
            return g_mgr.get_service_account_type(account_id) in ALLOWED_SERVICE_ACCOUNT_TYPES
    except Exception:
        return False

