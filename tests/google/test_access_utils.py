import pytest

from mock import patch

import fence
from fence.models import (
    UserServiceAccount,
    ServiceAccountAccessPrivilege,
    ServiceAccountToGoogleBucketAccessGroup,
)
from fence.resources.google.access_utils import (
    is_valid_service_account_type,
    service_account_has_external_access,
    google_project_has_valid_membership,
    google_project_has_valid_service_accounts,
    _force_remove_service_account_from_access_db,
    force_remove_service_account_from_access
)
from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    COMPUTE_ENGINE_API_SERVICE_ACCOUNT,
    GOOGLE_API_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
)
from cirrus.google_cloud.errors import GoogleAPIError

from cirrus.google_cloud.iam import (
    GooglePolicyMember
)

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data

def test_is_valid_service_account_type_compute_engine_default(cloud_manager):
    """
    Test that COMPUTE_ENGINE_DEFAULT is a valid service account type
    for service account registration
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT
    assert is_valid_service_account_type(cloud_manager.project_id, 1)


def test_not_valid_service_account_type_google_api(cloud_manager):
    """
    Test that GOOGLE_API is not a valid service account type
    for service account registration
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = GOOGLE_API_SERVICE_ACCOUNT
    assert not is_valid_service_account_type(cloud_manager.project_id, 1)


def test_not_valid_service_account_type_compute_engine_api(cloud_manager):
    """
    Test that COMPUTE_ENGINE_API is not a valid service account type
    for service account registration
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = COMPUTE_ENGINE_API_SERVICE_ACCOUNT
    assert not is_valid_service_account_type(cloud_manager.project_id, 1)


def test_is_valid_service_account_type_user_managed(cloud_manager):
    """
    Test that USER_MANAGED is a valid service account type
    for service account registration
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_type.return_value
    ) = USER_MANAGED_SERVICE_ACCOUNT
    assert is_valid_service_account_type(cloud_manager.project_id, 1)


def test_service_account_has_role_in_service_policy(cloud_manager):
    """
    Test service account has roles in its policy
    """
    faked_json = {
        "bindings": [
            {
                "role": "roles/owner",
                "members": [
                    "user:mike@example.com",
                    "group:admins@example.com",
                    "domain:google.com",
                    "serviceAccount:my-other-app@appspot.gserviceaccount.com",
                ]
            },
            {
                "role": "roles/viewer",
                "members": ["user:sean@example.com"]
            }
        ]
    }

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    assert service_account_has_external_access('test_service_account')


def test_service_account_has_user_managed_key_in_service_policy(cloud_manager):
    """
    Test that service account has user managed keys in its policy
    """
    faked_json = {
        'etag': 'ACAB'
    }

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_keys_inf.return_value
    ) = ['key1', 'key2']

    assert service_account_has_external_access('test_service_account')


def test_service_account_does_not_have_external_access(cloud_manager):
    """
    Test that service account does not have any role or user managed key in its policy
    """
    faked_json = {
        'etag': 'ACAB'
    }

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_keys_info.return_value
    ) = []
    assert not service_account_has_external_access('test_service_account')


def test_service_account_has_external_access_raise_exception(cloud_manager):
    """
    In the case that a exception is raised when there is no access to the service account policy
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse({}, 403)

    with pytest.raises(GoogleAPIError):
        assert service_account_has_external_access('test_service_account')


def test_project_has_valid_membership(cloud_manager, db_session):
    """
    Test that a project with only users and service acounts
    has valid membership
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_project_membership.return_value
    ) = [
        GooglePolicyMember("user", "user@gmail.com"),
        GooglePolicyMember("serviceAccount", "sa@gmail.com")
        ]

    get_users_mock = MagicMock()

    # note these are user ids but we're really just mocking this to
    # not error out on the members created above. e.g. this is faking
    # that these users exist in our db
    get_users_mock.return_value = [0, 1]
    get_users_patcher = patch(
        'fence.resources.google.access_utils.get_user_ids_from_google_members',
        get_users_mock
    )
    get_users_patcher.start()
    assert google_project_has_valid_membership(cloud_manager.project_id)
    get_users_patcher.stop()


def test_project_has_invalid_membership(cloud_manager, db_session):
    """
    Test that a project with a non-users or service acounts
     has invalid membership
     """
    (
        cloud_manager.return_value.__enter__.return_value.get_project_membership.return_value
    ) = [
        GooglePolicyMember("user", "user@gmail.com"),
        GooglePolicyMember("otherType", "other@gmail.com")
    ]
    assert not google_project_has_valid_membership(cloud_manager.project_id)


def test_project_has_valid_service_accounts(cloud_manager):
    """
    Test that a project has only valid service accounts
    """
    # set up fake service accounts
    (
        cloud_manager.return_value.__enter__.return_value
            .get_all_service_accounts.return_value
    ) = [
        {
            'name': 'fakeSA1',
            'email': 'a@gmail.com'
        },
        {
            'name': 'fakeSA2',
            'email': 'b@gmail.com'
        }
    ]

    # set up fake policy
    faked_json = {
        'etag': 'ACAB'
    }

    # set up fake policy return
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    # set up fake service account keys
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_keys_info.return_value
    ) = []

    assert google_project_has_valid_service_accounts(cloud_manager.project_id)


def test_project_has_invalid_service_accounts_external_access(cloud_manager):
    """
    Test that a project has invalid service accounts due to external access
    """
    # set up fake service accounts
    (
        cloud_manager.return_value.__enter__.return_value
            .get_all_service_accounts.return_value
    ) = [
        {
            'name': 'fakeSA1',
            'email': 'a@gmail.com'
        },
        {
            'name': 'fakeSA2',
            'email': 'b@gmail.com'
        }
    ]

    # set up fake policy, with bindings
    # indicates that service account 'a@gmail.com'
    # has external access
    faked_json = {
        'etag': 'ACAB',
        'bindings':
            [
                {
                    'role': 'Admin',
                    'members':
                    [
                        'serviceAccount:a@gmail.com'
                    ]
                }
            ]
    }

    # set up fake service account policy return
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    # set up fake service account keys
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_keys_info.return_value
    ) = []

    # invalid because service account 'a@gmail.com' has external access
    assert not google_project_has_valid_service_accounts(cloud_manager.project_id)


def test_project_has_invalid_service_accounts_keys(cloud_manager):
    """
    Test that a project has invalid service account keys
    because service account keys is non-empty
    """
    # set up fake service accounts
    (
        cloud_manager.return_value.__enter__.return_value
            .get_all_service_accounts.return_value
    ) = [
        {
            'name': 'fakeSA1',
            'email': 'a@gmail.com'
        },
        {
            'name': 'fakeSA2',
            'email': 'b@gmail.com'
        }
    ]

    # set up fake policy
    faked_json = {
        'etag': 'ACAB'
    }

    # set up fake policy return value
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    # set up fake service account keys,
    # non-empty key return is invalid
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_keys_info.return_value
    ) = ['not empty']

    # invalid because service account keys is non-empty
    assert not google_project_has_valid_service_accounts(cloud_manager.project_id)


def test_project_has_valid_service_accounts_membership(cloud_manager):
    """
    Test that a project has valid service accounts,
    including check that all service accounts in IAM policy
    are from this project
    """
    # set up fake service accounts
    (
        cloud_manager.return_value.__enter__.return_value
            .get_all_service_accounts.return_value
    ) = [
        {
            'name': 'fakeSA1',
            'email': 'a@gmail.com'
        },
        {
            'name': 'fakeSA2',
            'email': 'b@gmail.com'
        }
    ]

    # set up fake policy, without any bindings
    faked_json = {
        'etag': 'ACAB'
    }

    # set up fake policy return value
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    # set up fake service account keys
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_keys_info.return_value
    ) = []

    # set up policy membership, only with service accounts
    # from this project
    (
        cloud_manager.return_value.__enter__.
            return_value.get_project_membership.return_value
    ) = [
        GooglePolicyMember(GooglePolicyMember.SERVICE_ACCOUNT,
                           'a@gmail.com'),
        GooglePolicyMember(GooglePolicyMember.SERVICE_ACCOUNT,
                           'b@gmail.com')
    ]

    assert google_project_has_valid_service_accounts(cloud_manager.project_id)


def test_project_has_invalid_service_accounts_membership(cloud_manager):
    """
    Test that a project has invalid service accounts,
    because not all service accounts in IAM policy belong
    to the project
    """
    # set up fake service accounts
    (
        cloud_manager.return_value.__enter__.return_value
            .get_all_service_accounts.return_value
    ) = [
        {
            'name': 'fakeSA1',
            'email': 'a@gmail.com'
        },
        {
            'name': 'fakeSA2',
            'email': 'b@gmail.com'
        }
    ]

    # set up fake policy without any bindings
    faked_json = {
        'etag': 'ACAB'
    }

    # set up fake account policy return
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_policy.return_value
    ) = MockResponse(faked_json, 200)

    # set up fake service account keys
    (
        cloud_manager.return_value.__enter__.
            return_value.get_service_account_keys_info.return_value
    ) = []

    # set up project membership
    # service account 'c@gmail.com is not from this project
    (
        cloud_manager.return_value.__enter__.
            return_value.get_project_membership.return_value
    ) = [
        GooglePolicyMember(GooglePolicyMember.SERVICE_ACCOUNT,
                           'a@gmail.com'),
        GooglePolicyMember(GooglePolicyMember.SERVICE_ACCOUNT,
                           'b@gmail.com'),
        GooglePolicyMember(GooglePolicyMember.SERVICE_ACCOUNT,
                           'c@gmail.com')
    ]

    # invalid because service account 'c@gmail.com is not from this project
    assert not google_project_has_valid_service_accounts(cloud_manager.project_id)


def test_remove_service_account_from_access(
        cloud_manager, db_session, setup_data):
    """
    Test that successfuly delete a given service account
    """
    force_remove_service_account_from_access('test@gmail.com', 'test')
    (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.return_value
    ) = {}

    service_account = (
        db_session.
        query(UserServiceAccount).
        filter_by(email='test@gmail.com').
        first()
    )

    access_projects = (
        db_session.
        query(ServiceAccountAccessPrivilege).
        filter_by(service_account_id=service_account.id).
        all()
    )

    assert service_account
    assert access_projects == []

    for access_group in  service_account.to_access_groups:
        assert not(
            db_session.
            query(ServiceAccountToGoogleBucketAccessGroup).
            filter_by(service_account_id=service_account.id, access_group_id=access_group.id).
            first()
        )

def test_remove_service_account_raise_NotFound_exc(
        cloud_manager, db_session, setup_data):
    """
    Test that raises an exception since the service account does not exist
    """
    with pytest.raises(fence.errors.NotFound):
        assert (
            force_remove_service_account_from_access('non_existed_service_account', 'test')
        )


def test_remove_service_account_raise_GoogleAPI_exc(
        cloud_manager, db_session, setup_data):
    """
    Test that raiseis an exception due to Google API errors
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.side_effect
    ) = Exception('exception')

    with pytest.raises(GoogleAPIError):
        assert force_remove_service_account_from_access('test@gmail.com', 'test')

