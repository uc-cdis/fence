"""
Utilities for determine access and validity for service account
registration.
"""
from flask_sqlalchemy_session import current_session
from fence.models import AccessPrivilege
from collections import Mapping

from fence.resources.google.utils import (
    get_registered_service_accounts,
    get_project_access_from_service_accounts
)


def get_google_project_validity_info(
        google_project, service_account=None, new_service_account_access=None,
        early_return=False):
    """
    Return a representation of the validity about a google project and
    optionally, provided service account and access.

    NOTE: with early_return=False, you will recieve a ValidityInfo object with
          information about all the validity checks

    Args:
        google_project (str): Google project identifier
        service_account (str, optional): an additional service account
            identifier (ex: email) to include when checking access. You can
            provide this without actually giving it access to check if access
            will be valid
        new_service_account_access (List(str), optional): List of
            Project.auth_ids to attempt to provide the new service account
            access to
        early_return (bool, optional): Whether or not to return early.
            PLEASE NOTE: if you specify early_return=True you are ONLY
                         gauranteed a boolean return

    Returns:
        bool: validity of the project. NOTE: You will recieve a ValidityInfo
              object if early_return=False. From this you can retrieve info
              about failing validity checks to determine what caused the issue
    """
    validity = ValidityInfo()
    provided_access = new_service_account_access or []

    project_validity = ValidityInfo()

    valid_parent_org = not google_project_has_parent_org(google_project)
    project_validity['valid_parent_org'] = valid_parent_org
    if not valid_parent_org and early_return:
        return False

    valid_membership = google_project_has_valid_membership(google_project)
    project_validity['valid_membership'] = valid_membership
    if not valid_membership and early_return:
        return False

    project_service_account_validity = (
        get_google_project_service_accounts_validity_info(google_project)
    )
    project_validity['service_accounts'] = project_service_account_validity
    if not project_service_account_validity and early_return:
        return False

    service_account_validity = None
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
    project_access_validity = (
        get_user_access_validity_info(
            google_project, service_account_access,
            early_return=early_return)
    )
    if not project_access_validity and early_return:
        return False

    validity['project'] = project_validity
    validity['access'] = project_access_validity
    if service_account_validity is not None:
        validity['service_account'] = service_account_validity

    return validity


def get_service_account_validity_info(
        google_project, service_account,
        early_return=False):
    """
    Return a representation of the validity about a google project's service
    account.

    NOTE: with early_return=False, you will recieve a ValidityInfo object with
          information about all the validity checks

    Args:
        google_project (str): Google project identifier
        service_account (TYPE): service account identifier to check validity of
        early_return (bool, optional): Whether or not to return early.
            PLEASE NOTE: if you specify early_return=True you are ONLY
                         gauranteed a boolean return

    Returns:
        fence.resources.google.access_utils.ValidityInfo:
            validity of the service account.

            NOTE: You will recieve a ValidityInfo object BUT it you specify
                early_return=True it WILL NOT have all the expected
                checks present. You should only use the response as a
                boolean if you specify early_return=True
    """
    validity = ValidityInfo()

    valid_type = is_valid_service_account_type(service_account)
    validity['valid_type'] = valid_type
    if not validity and early_return:
        return validity

    no_external_access = (
        service_account_has_external_access(service_account)
    )
    validity['no_external_access'] = no_external_access
    if not validity and early_return:
        return validity

    is_owned_by_google_project = (
        is_service_account_from_google_project(service_account, google_project)
    )
    validity['owned_by_project'] = is_owned_by_google_project
    if not validity and early_return:
        return validity

    return validity


def get_google_project_service_accounts_validity_info(
        google_project, early_return=False):
    """
    Return a representation of the validity about a google project's
    service accounts.

    NOTE: with early_return=False, you will recieve a ValidityInfo object with
          information about all the validity checks

    Args:
        google_project (str): Google project identifier
        service_account (TYPE): service account identifier to check validity of
        early_return (bool, optional): Whether or not to return early.
            PLEASE NOTE: if you specify early_return=True you are ONLY
                         gauranteed a boolean return

    Returns:
        fence.resources.google.access_utils.ValidityInfo:
            validity of the google project service accounts.

            NOTE: You will recieve a ValidityInfo object BUT it you specify
                early_return=True it WILL NOT have all the expected
                checks present. You should only use the response as a
                boolean if you specify early_return=True
    """
    service_accounts = []  # TODO get ids from project

    validity = ValidityInfo()

    for service_account in service_accounts:
        service_account_validity_info = get_service_account_validity_info(
            google_project, service_account, early_return=early_return
        )
        service_account_id = str(service_account)  # TODO should be email

        # one bad apple makes project invalid
        validity[str(service_account_id)] = service_account_validity_info
        if not validity and early_return:
            return validity

    return validity


def get_user_access_validity_info(
        google_project, project_access, early_return=False):
    """
    Return a representation of the validity about a google project's
    service accounts.

    NOTE: with early_return=False, you will recieve a ValidityInfo object with
          information about all the validity checks

    Args:
        google_project (str): Google project identifier
        project_access (List(str)): List of Project.auth_ids to represent
            what access to check for the google project
        early_return (bool, optional): Whether or not to return early.
            PLEASE NOTE: if you specify early_return=True you are ONLY
                         gauranteed a boolean return

    Returns:
        fence.resources.google.access_utils.ValidityInfo:
            validity of the user access.

            NOTE: You will recieve a ValidityInfo object BUT it you specify
                early_return=True it WILL NOT have all the expected
                checks present. You should only use the response as a
                boolean if you specify early_return=True
    """
    validity = ValidityInfo()

    # TODO get all members on google project
    project_members = []

    all_user_ids = get_user_ids_from_google_members(project_members)

    for project in project_access:
        project_validity_info = do_all_users_have_access_to_project(
            all_user_ids, project)

        validity[str(project)] = project_validity_info
        if not validity and early_return:
            return validity

    return validity


def google_project_has_parent_org(google_project):
    return True


def google_project_has_valid_membership(google_project):
    return False


def is_valid_service_account_type(service_account):
    return False


def service_account_has_external_access(service_account):
    return True


def is_service_account_from_google_project(service_account, google_project):
    return False


def is_user_member_of_all_google_projects(user_id, google_project_ids):
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


def get_user_ids_from_google_members(members):
    # TODO actually get from our db. search users and linked google accounts
    return []


def do_all_users_have_access_to_project(user_ids, project_auth_id):
    # user_ids will be list of user ids
    # check if all user ids has access to a project with project_auth_id
    for user_id in user_ids:
        access_privillege = current_session.query(AccessPrivilege).filter(AccessPrivilege.user_id == user_id and AccessPrivilege.project_id == project_auth_id).first()
        if access_privillege is None:
            return False
    return True


class ValidityInfo(Mapping):
    """
    Dict-like object to hold a boolean value representing validity along with
    information about the validity.

    If the info is false-y, the validity of this object will evaluate to False.

    This means that you can nest ValidityInfo objects and
    the "valid" status of the parent object will always be updated when adding
    new validity information
    """
    def __init__(self, default_validity=True):
        self._valid = default_validity
        self._info = {}

    def get(self, key, *args):
        return self._info.get(key, *args)

    def __setitem__(self, key, value):
        if not value:
            self._valid = False
        self._info.__setitem__(key, value)

    def __contains__(self, key):
        return key in self._info

    def __iter__(self):
        for key, value in self._info.iteritems():
            yield key, value

    def __getitem__(self, key):
        return self._info[key]

    def __delitem__(self, key):
        del self._info[key]

    def __len__(self):
        return len(self._info)

    def __bool__(self):
        return self._valid

    def __nonzero__(self):
        return self._valid

    def __str__(self):
        return str({
            'valid': self._valid,
            'info': str(self._info)
        })
