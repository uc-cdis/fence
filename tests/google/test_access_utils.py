from fence.resources.google.access_utils import (
    is_valid_service_account_type,
)
from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT,
    COMPUTE_ENGINE_API,
    GOOGLE_API,
    USER_MANAGED,
)


def test_is_valid_service_account(cloud_manager):

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = COMPUTE_ENGINE_DEFAULT
    assert is_valid_service_account_type(cloud_manager.project_id, 1)

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = GOOGLE_API
    assert not is_valid_service_account_type(cloud_manager.project_id, 1)

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = COMPUTE_ENGINE_API
    assert not is_valid_service_account_type(cloud_manager.project_id, 1)

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = USER_MANAGED
    assert is_valid_service_account_type(cloud_manager.project_id, 1)
