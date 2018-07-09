"""
Utilities for determine access and validity for service account
registration.
"""
from fence.resources.google.utils import (
    get_registered_service_accounts,
    get_project_access_from_service_accounts
)


class ValidityInfo(object):

    def __init__(self, default_validity=True):
        self.valid = default_validity
        self.info = {}

    def get(self, key):
        return self.info.get(key)

    def add(self, key, info):
        if not info:
            self.valid = False
        self.info[key] = info

    def __bool__(self):
        return self.valid


def get_project_validity_info(
        google_project, service_account=None, new_service_account_access=None,
        early_return=False):
    """
    Return a ValidityInfo object representing the validity information about
    the google project and optionally, provided service account addition.

    Args:
        google_project (TYPE): Description
        service_account (None, optional): Description
        new_service_account_access (None, optional): Description
        early_return (bool, optional): Whether or not to return early

    Returns:
        TYPE: Description
    """
    # service_account is an additional service account to
    #     include when checking access. You can provide this without actually
    #     giving it access to check if access will be valid
    # new_service_account_access is a list of auth_ids to attempt to provide
    #     the new account access to
    validity = ValidityInfo()
    project_validity = ValidityInfo()
    project_access_validity = ValidityInfo()
    service_account_validity = None

    provided_access = new_service_account_access or []

    valid_parent_org = not project_has_parent_org(google_project)
    project_validity.add('valid_parent_org', valid_parent_org)
    if not valid_parent_org and early_return:
        return False

    valid_membership = project_has_valid_membership(google_project)
    project_validity.add('valid_membership', valid_membership)
    if not valid_membership and early_return:
        return False

    project_service_account_validity = (
        get_project_service_accounts_validity_info(google_project)
    )
    project_validity.add('service_accounts', project_service_account_validity)
    if not project_service_account_validity and early_return:
        return False

    if service_account:
        service_account_validity = get_service_account_validity_info(
            google_project, service_account, early_return=early_return
        )
        if not service_account_validity and early_return:
            return False

    # get the service accounts for the project to determine all the data the
    # project can access through the service accounts
    service_accounts = get_registered_service_accounts(google_project)
    service_account_access = (
        get_project_access_from_service_accounts(service_accounts)
    )

    # extend list with any provided access to test
    service_account_access.extend(provided_access)

    # make sure all the users of the project actually have access to all the
    # data the service accounts have access to
    valid_access = (
        users_have_valid_access(google_project, service_account_access)
    )
    project_access_validity.add('user_access', valid_access)
    if not valid_access and early_return:
        return False

    validity.add('project', project_validity)
    validity.add('access', project_access_validity)
    if service_account_validity is not None:
        validity.add('service_account', service_account_validity)

    return validity


def get_service_account_validity_info(
        google_project, service_account,
        early_return=False):
    validity = ValidityInfo()

    valid_type = is_valid_service_account_type(service_account)
    validity.add('valid_type', valid_type)
    if not validity and early_return:
        return False

    no_external_access = (
        service_account_has_external_access(service_account)
    )
    validity.add('no_external_access', no_external_access)
    if not validity and early_return:
        return False

    is_owned_by_project = (
        is_service_account_from_project(service_account, google_project)
    )
    validity.add('owned_by_project', is_owned_by_project)
    if not validity and early_return:
        return False

    return validity


def get_project_service_accounts_validity_info(
        google_project, early_return=False):
    service_accounts = []  # TODO get ids from project

    validity = ValidityInfo()

    for service_account in service_accounts:
        service_account_validity_info = get_service_account_validity_info(
            google_project, service_account, early_return=early_return
        )
        service_account_id = str(service_account)  # TODO should be email

        # one bad apple makes project invalid
        validity.add(str(service_account_id), service_account_validity_info)
        if not validity and early_return:
            return False

    return validity


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


# TODO expand to have a validity_info object with project: valid
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
