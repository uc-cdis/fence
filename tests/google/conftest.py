from addict import Dict
import jwt
import pytest

from fence.models import (
    Project,
    Bucket,
    CloudProvider,
    UserServiceAccount,
    ServiceAccountToGoogleBucketAccessGroup,
    GoogleBucketAccessGroup,
    ServiceAccountAccessPrivilege,
)

from tests import utils

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch


@pytest.fixture(scope='function')
def encoded_jwt_service_accounts_access(
        kid, rsa_private_key, user_client, oauth_client):
    """
    Return a JWT and user_id for a new user containing the claims and
    encoded with the private key.

    Args:
        claims (dict): fixture
        rsa_private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {'kid': kid}
    return Dict(
        jwt=jwt.encode(
            utils.authorized_service_account_management_claims(
                user_client['username'], user_client['user_id'],
                oauth_client['client_id']),
            key=rsa_private_key,
            headers=headers,
            algorithm='RS256',
        ),
        user_id=user_client['user_id'],
        client_id=oauth_client['client_id']
    )


@pytest.fixture(scope='function')
def valid_service_account_patcher():
    patches = []

    valid_type_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.access_utils.is_valid_service_account_type',
        valid_type_mock
    ))
    patches.append(patch(
        'fence.resources.google.validity.is_valid_service_account_type',
        valid_type_mock
    ))

    external_access_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.access_utils.service_account_has_external_access',
        external_access_mock
    ))
    patches.append(patch(
        'fence.resources.google.validity.service_account_has_external_access',
        external_access_mock
    ))

    from_google_project_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.access_utils.is_service_account_from_google_project',
        from_google_project_mock
    ))
    patches.append(patch(
        'fence.resources.google.validity.is_service_account_from_google_project',
        from_google_project_mock
    ))

    valid_type_mock.return_value = True
    external_access_mock.return_value = False
    from_google_project_mock.return_value = True

    for patched_function in patches:
        patched_function.start()

    yield {
        'is_valid_service_account_type': (
            valid_type_mock
        ),
        'service_account_has_external_access': (
            external_access_mock
        ),
        'is_service_account_from_google_project': (
            from_google_project_mock
        ),
    }

    for patched_function in patches:
        patched_function.stop()


@pytest.fixture(scope='function')
def valid_google_project_patcher():
    patches = []

    parent_org_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.access_utils.google_project_has_parent_org',
        parent_org_mock
    ))
    patches.append(patch(
        'fence.resources.google.validity.google_project_has_parent_org',
        parent_org_mock
    ))

    valid_membership_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.access_utils.google_project_has_valid_membership',
        valid_membership_mock
    ))
    patches.append(patch(
        'fence.resources.google.validity.google_project_has_valid_membership',
        valid_membership_mock
    ))

    users_have_access_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.access_utils.do_all_users_have_access_to_project',
        users_have_access_mock
    ))
    patches.append(patch(
        'fence.resources.google.validity.do_all_users_have_access_to_project',
        users_have_access_mock
    ))

    get_registered_service_accounts_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.validity.get_registered_service_accounts',
        get_registered_service_accounts_mock
    ))

    project_access_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.validity.get_project_access_from_service_accounts',
        project_access_mock
    ))

    project_service_accounts_mock = MagicMock()
    patches.append(patch(
        'fence.resources.google.validity.get_service_account_ids_from_google_project',
        project_service_accounts_mock
    ))

    parent_org_mock.return_value = False
    valid_membership_mock.return_value = True
    users_have_access_mock.return_value = True

    for patched_function in patches:
        patched_function.start()

    yield {
        'google_project_has_parent_org': (
            parent_org_mock
        ),
        'google_project_has_valid_membership': (
            valid_membership_mock
        ),
        'do_all_users_have_access_to_project': (
            users_have_access_mock
        ),
        'get_registered_service_accounts': (
            get_registered_service_accounts_mock
        ),
        'get_project_access_from_service_accounts': (
            project_access_mock
        ),
        'get_service_account_ids_from_google_project': (
            project_service_accounts_mock
        ),
    }

    for patched_function in patches:
        patched_function.stop()


@pytest.fixture(scope='function')
def invalid_service_account_patcher():
    invalid_service_account = 'invalid@example.com'

    def mock_is_valid(sa_email, *args, **kwargs):
        if sa_email == invalid_service_account:
            return False
        return True

    patcher = patch(
        'fence.scripting.google_monitor._is_valid_service_account',
        mock_is_valid
    )

    patcher.start()
    yield invalid_service_account
    patcher.stop()


@pytest.fixture(scope='function')
def setup_data(db_session):
    cp = CloudProvider(name='test', endpoint='http://test.endpt')
    user = UserServiceAccount(
            google_unique_id='test_id',
            email='test@gmail.com',
            google_project_id='test'
    )
    db_session.add(user)
    db_session.add(cp)
    db_session.commit()

    project1 = Project(name='test_1', auth_id='test_auth_1')
    project2 = Project(name='test_2', auth_id='test_auth_2')

    db_session.add(project1)
    db_session.add(project2)

    bucket = Bucket(name='bucket1', provider_id=cp.id)
    db_session.add(bucket)
    db_session.commit()

    db_session.add(ServiceAccountAccessPrivilege(project_id=project1.id, service_account_id=user.id))
    db_session.add(ServiceAccountAccessPrivilege(project_id=project2.id, service_account_id=user.id))

    access_grp = GoogleBucketAccessGroup(
        bucket_id=bucket.id, email='test@gmail.com'
    )

    db_session.add(access_grp)
    db_session.commit()

    service_account_grp = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=user.id, access_group_id=access_grp.id
    )
    db_session.add(service_account_grp)
    db_session.commit()
