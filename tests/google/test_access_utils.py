import pytest
import time
# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch
from sqlalchemy import or_

from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    COMPUTE_ENGINE_API_SERVICE_ACCOUNT,
    GOOGLE_API_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
)
from cirrus.google_cloud.iam import (
    GooglePolicyMember
)

import fence
from fence.models import (
    Project,
    UserServiceAccount,
    ServiceAccountAccessPrivilege,
    ServiceAccountToGoogleBucketAccessGroup,
)
from fence.resources.google.access_utils import (
    is_valid_service_account_type,
    service_account_has_external_access,
    get_google_project_valid_users_and_service_accounts,
    _force_remove_service_account_from_access_db,
    force_remove_service_account_from_access,
    extend_service_account_access,
    get_current_service_account_project_access,
    patch_user_service_account,
    remove_white_listed_service_account_ids,
)


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

    assert service_account_has_external_access('test_service_account', cloud_manager.project_id)


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

    assert service_account_has_external_access('test_service_account', cloud_manager.project_id)


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
    assert not service_account_has_external_access('test_service_account', cloud_manager.project_id)


def test_service_account_has_external_access_raise_exception(cloud_manager):
    """
    In the case that a exception is raised when there is no access to the service account policy
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.get_service_account_policy.return_value
    ) = MockResponse({}, 403)

    with pytest.raises(Exception):
        assert service_account_has_external_access('test_service_account', cloud_manager.project_id)


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
        'fence.resources.google.access_utils.get_users_from_google_members',
        get_users_mock
    )
    get_users_patcher.start()
    assert get_google_project_valid_users_and_service_accounts(cloud_manager.project_id)
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
    with pytest.raises(Exception):
        get_google_project_valid_users_and_service_accounts(cloud_manager.project_id)


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

    for access_group in service_account.to_access_groups:
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

    with pytest.raises(Exception):
        assert force_remove_service_account_from_access('test@gmail.com', 'test')


def test_extend_service_account_access(
        db_session, register_user_service_account):
    """
    Test that we can successfully update the db and extend access for a
    service account
    """
    service_account = register_user_service_account['service_account']

    extend_service_account_access(service_account.email)

    service_account_accesses = (
        db_session.query(
            ServiceAccountToGoogleBucketAccessGroup)
        .filter_by(service_account_id=service_account.id)
    ).all()

    assert (
        len(service_account_accesses)
        == len(register_user_service_account['bucket_access_groups'])
    )

    # make sure we actually extended access past the current time
    for access in service_account_accesses:
        assert access.expires > int(time.time())


def test_get_current_service_account_project_access(
        db_session, register_user_service_account):
    """
    Test that we get all the correct info for a service accounts project
    access.
    """
    service_account = register_user_service_account['service_account']
    project_auth_ids = [
        project.auth_id
        for project in register_user_service_account['projects']
    ]

    access = get_current_service_account_project_access(service_account.email)

    assert access == project_auth_ids

def test_update_user_service_account_success(cloud_manager, db_session, setup_data):
    """
    test@gmail.com has access to test_auth_1 and test_auth_2 already
    Test that successfully update service account access so that
    the 'test_auth2' will be removed from access project list

    """
    (
        cloud_manager.return_value.__enter__.
        return_value.add_member_to_group.return_value
    ) = {}
    (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.return_value
    ) = {}

    service_account = (
            db_session
            .query(UserServiceAccount)
            .filter_by(email='test@gmail.com')
            .first()
        )

    accessed_projects = (
        db_session
        .query(ServiceAccountAccessPrivilege)
        .filter_by(service_account_id=service_account.id)
        .all()
    )

    accessed_bucket_grps = (
        db_session.
        query(ServiceAccountToGoogleBucketAccessGroup).
        filter_by(service_account_id=service_account.id).
        all()
    )

    assert len(accessed_projects) == 2
    assert len(accessed_bucket_grps) == 2
    patch_user_service_account('test', 'test@gmail.com', ['test_auth_1'])

    project = (
            db_session
            .query(Project)
            .filter_by(auth_id='test_auth_1')
            .first()
    )

    project_ids = [
        project.id for project in (
            db_session
            .query(ServiceAccountAccessPrivilege)
            .filter_by(service_account_id=service_account.id)
            .all()
        )
    ]
    assert len(project_ids) == 1
    assert project_ids[0] == project.id

    accessed_bucket_grps = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .filter_by(service_account_id=service_account.id)
        .all()
    )
    assert len(accessed_bucket_grps) == 1


def test_update_user_service_account_success2(cloud_manager, db_session, setup_data):
    """
    test@gmail.com has access to test_auth_1 and test_auth_2 already
    Test that successfully update service account access so that
    the 'test_auth1, test_auth2' will be removed from access project list
    while 'test_auth3' is added to the list
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.add_member_to_group.return_value
    ) = {
            "kind": "admin#directory#member",
            "etag": "test_etag",
            "id": "test_id",
            "email": "test@g,ail.com",
            "role": "test_role",
            "type": "test_type"
        }
    (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.return_value
    ) = {}

    service_account = (
            db_session
            .query(UserServiceAccount)
            .filter_by(email='test@gmail.com')
            .first()
            )

    accessed_projects = (
        db_session
        .query(ServiceAccountAccessPrivilege)
        .filter_by(service_account_id=service_account.id)
        .all()
    )

    accessed_bucket_grps = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .filter_by(service_account_id=service_account.id)
        .all()
    )

    assert len(accessed_projects) == 2
    assert len(accessed_bucket_grps) == 2
    patch_user_service_account('test', 'test@gmail.com', ['test_auth_3'])

    project = (
        db_session
        .query(Project)
        .filter_by(auth_id='test_auth_3')
        .first()
    )
    access_privileges = (
        db_session
        .query(ServiceAccountAccessPrivilege)
        .filter_by(service_account_id=service_account.id)
        .all()
    )
    assert len(access_privileges) == 1
    assert access_privileges[0].project_id == project.id

    accessed_bucket_grps = (
        db_session
        .query(ServiceAccountToGoogleBucketAccessGroup)
        .filter_by(service_account_id=service_account.id)
        .all()
    )
    assert len(accessed_bucket_grps) == 1


def test_update_user_service_account_success3(cloud_manager, db_session, setup_data):
    """
    test@gmail.com has access to test_auth_1 and test_auth_2 already
    Test that there is no add and delete operations when client try to update
    with projects already granted access
    """
    service_account = (
            db_session
            .query(UserServiceAccount)
            .filter_by(email='test@gmail.com')
            .first()
        )
    patch_user_service_account('test', 'test@gmail.com', ['test_auth_1', 'test_auth_2'])

    assert not (
        cloud_manager.return_value.__enter__.
        return_value.add_member_to_group.called
    )

    assert not (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.called
    )

    project_ids1 = {
        project.id for project in (
            db_session
            .query(Project)
            .filter(or_(Project.auth_id=='test_auth_1', Project.auth_id=='test_auth_2'))
            .all()
         )
    }

    project_ids2 = {
        access_privilege.project_id for access_privilege in (
            db_session
            .query(ServiceAccountAccessPrivilege)
            .filter_by(service_account_id=service_account.id)
            .all()
        )
    }
    assert project_ids1 == project_ids2


def test_update_user_service_account_raise_NotFound_exc(
        cloud_manager, db_session, setup_data):
    """
    Test that raises an exception since the service account does not exist
    """
    with pytest.raises(fence.errors.NotFound):
        assert (
            patch_user_service_account('google_test', 'non_existed_service_account', ['test_auth_1'])
        )


def test_update_service_account_fail_no_project(cloud_manager, db_session, setup_data):
    """
    Test that raises an exception since a provided project does not exist
    """
    with pytest.raises(fence.errors.NotFound):
        assert (
            patch_user_service_account('google_test', 'test@gmail.com', ['no_project_auth'])
        )


def test_update_user_service_account_raise_GoogleAPI_exc(
        cloud_manager, db_session, setup_data):
    """
    Test that raises an exception due to Google API errors
    during removing members from google groups
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.remove_member_from_group.side_effect
    ) = Exception('exception')

    with pytest.raises(Exception):
        assert patch_user_service_account('test', 'test@gmail.com', ['test_auth_2'])


def test_update_user_service_account_raise_GoogleAPI_exc2(
        cloud_manager, db_session, setup_data):
    """
    Test that raises an exception due to Google API errors
    during adding members to google groups
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.add_member_to_group.side_effect
    ) = Exception('exception')

    with pytest.raises(Exception):
        assert patch_user_service_account('test', 'test@gmail.com', ['test_auth_1', 'test_auth_2','test_auth_3'])


def test_update_user_service_account_raise_GoogleAPI_exc3(
        cloud_manager, db_session, setup_data):
    """
    Test that raises an exception due to Google API errors
    during adding members to google groups
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.add_member_to_group.return_value
        ) = {'a': 'b'}

    with pytest.raises(Exception):
        assert patch_user_service_account('test', 'test@gmail.com', ['test_auth_1', 'test_auth_2','test_auth_3'])


def test_update_user_service_account_raise_GoogleAPI_exc4(
        cloud_manager, db_session, setup_data):
    """
    Test that raises an exception due to Google API errors
    during deleting members to google groups
    """
    (
        cloud_manager.return_value.__enter__.
        return_value.delete_member_from_group.return_value
        ) = {'a': 'b'}

    with pytest.raises(Exception):
        assert patch_user_service_account('test', 'test@gmail.com', ['test_auth_1'])


def test_whitelisted_service_accounts(app, db_session, client,
                                      encoded_jwt_service_accounts_access, cloud_manager,
                                      valid_google_project_patcher, valid_service_account_patcher):
    service_account_ids = ['test@123', 'test@456', 'test@789']
    remove_white_listed_service_account_ids(service_account_ids)
    assert 'test@123' not in service_account_ids
    assert 'test@456' not in service_account_ids
    assert 'test@789' in service_account_ids
