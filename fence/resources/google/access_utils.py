from cirrus.google_cloud.manager import (
    COMPUTE_ENGINE_DEFAULT,
    GOOGLE_API,
    COMPUTE_ENGINE_API,
    USER_MANAGED,
)

ALLOWED_SERVICE_ACCOUNT_TYPES = [
    COMPUTE_ENGINE_DEFAULT,
    USER_MANAGED,
]

def is_valid_service_account_type(self, account_id):

    sa = self.get_service_account(account_id)
    if sa:
        return self._service_account_type(sa) in ALLOWED_SERVICE_ACCOUNT_TYPES
    else:
        return False