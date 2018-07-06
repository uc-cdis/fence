"""
Utilities for determine access and validity for service account
registration.
"""
from fence.resources.google.utils import (
    get_registered_service_accounts,
    get_project_access_from_service_accounts
)


def is_project_valid(google_project, service_accounts=None):
    # service_accounts is a list of additional service accounts to
    # include when checking access. You can provide this without actually
    # giving it access to check if access will be valid
    provided_service_accounts = service_accounts or []

    valid_project = not project_has_parent_org(google_project)
    valid_service_accounts = project_has_valid_service_accounts(google_project)
    valid_membership = project_has_valid_membership(google_project)

    service_accounts = get_registered_service_accounts(google_project)
    service_accounts.append(provided_service_accounts)
    service_account_access = get_project_access_from_service_accounts(service_accounts)

    valid_access = users_have_valid_access(google_project, service_account_access)

    return (
        valid_project
        and valid_service_accounts
        and valid_membership
        and valid_access
    )


def project_has_valid_service_accounts(google_project):
    service_accounts = []  # TODO get from project
    for service_account in service_accounts:
        if not is_valid_service_account_type(service_account):
            return False

        if service_account_has_external_access(service_account):
            return False

        if not is_service_account_from_project(service_account, google_project):
            return False

    return True


def project_has_parent_org(google_project):
    return True


def project_has_valid_membership(google_project):
    return False


def is_valid_service_account_type(service_account):
    return False


def service_account_has_external_access(service_account):
    return True


def is_service_account_from_project(service_account, google_project):
    return False


def users_have_valid_access(google_project, project_access):
    return False


def is_user_member_of_all_projects(user_id, google_project_ids):
    """
    Return whether or not the given user is a member of ALL of the provided
    Google project IDs.

    This will verify that either the user's email or their linked Google
    account email exists as a member in the projects.

    Args:
        user_id (int): User identifier
        google_project_ids (List(str)): List of unique google project ids

    Returns:
        bool: whether or not the given user is a member of ALL of the provided
              Google project IDs
    """
    # TODO actually check
    return False
