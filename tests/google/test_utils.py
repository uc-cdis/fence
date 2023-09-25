from unittest.mock import patch, MagicMock

import pytest

from fence.resources.google.utils import (
    give_service_account_billing_access_if_necessary,
    GoogleCloudManager,
)
from fence.utils import DEFAULT_BACKOFF_SETTINGS


def test_give_service_account_billing_access_if_necessary_fails(cloud_manager):
    """
    Tests that the GCM give_service_account_billing_access backs off the right number of times when
    give_service_account_billing_access_if_necessary calls it.
    """

    sa_private_key = {"client_email": "paying_requestor@somewhere.com"}
    r_pays_project = "some_project_id"

    # Grab the GCM instance from the with block in _give_service_account_billing_access
    cloud_manager_instance = cloud_manager.return_value.__enter__.return_value
    # Set the GCM method to raise an exception.
    cloud_manager_instance.give_service_account_billing_access.side_effect = Exception(
        "Something's wrong"
    )

    with pytest.raises(Exception):
        give_service_account_billing_access_if_necessary(sa_private_key, r_pays_project)

    assert (
        cloud_manager_instance.give_service_account_billing_access.call_count
        == DEFAULT_BACKOFF_SETTINGS["max_tries"]
    )
