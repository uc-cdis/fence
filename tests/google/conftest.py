from addict import Dict
import jwt
import pytest

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
