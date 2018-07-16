import flask

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
    """
    Checks service account type against allowed service account types
    for service account registration

    Args:
        project_id(str): project identifier for project associated
            with service account
        account_id(str): account identifier to check valid type

    Returns:
        Bool: True if service acocunt type is allowed as defined
        in ALLOWED_SERVICE_ACCOUNT_TYPES
    """
    try:
        with GoogleCloudManager(project_id) as g_mgr:
            return (g_mgr.
                    get_service_account_type(account_id)
                    in ALLOWED_SERVICE_ACCOUNT_TYPES)
    except Exception as exc:
        flask.current_app.logger.debug((
            'validity of Google service account {} (google project: {}) type '
            'determined False due to error. Details: {}').
            format(account_id, project_id, exc))
        return False

