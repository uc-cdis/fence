"""
Utilities for determine access and validity for service account
registration.
"""
from flask_sqlalchemy_session import current_session
from fence.models import AccessPrivilege


def can_user_manage_service_account(user_id, account_id):
    """
    Return whether or not the user has permission to update and/or delete the
    given service account.

    Args:
        user_id (int): user's identifier
        account_id (str): service account identifier

    Returns:
        bool: Whether or not the user has permission
    """
    service_account_email = get_service_account_email(account_id)
    service_account_project = (
        get_google_project_from_service_account_email(service_account_email)
    )

    # check if user is on project
    return is_user_member_of_all_google_projects(
        user_id, [service_account_project])


def google_project_has_parent_org(google_project):
    raise NotImplementedError('Functionality not yet available...')


def google_project_has_valid_membership(google_project):
    raise NotImplementedError('Functionality not yet available...')


def is_valid_service_account_type(service_account):
    raise NotImplementedError('Functionality not yet available...')


def service_account_has_external_access(service_account):
    raise NotImplementedError('Functionality not yet available...')


def is_service_account_from_google_project(service_account, google_project):
    raise NotImplementedError('Functionality not yet available...')


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
    raise NotImplementedError('Functionality not yet available...')


def do_all_users_have_access_to_project(user_ids, project_auth_id):
    # user_ids will be list of user ids
    # check if all user ids has access to a project with project_auth_id
    for user_id in user_ids:
        access_privillege = current_session.query(AccessPrivilege).filter(
            AccessPrivilege.user_id == user_id and AccessPrivilege.project_id == project_auth_id).first()
        if access_privillege is None:
            return False

    return True


# TODO this should be in cirrus rather than fence...
def get_service_account_email(account_id):
    # first check if the account_id is an email, if not, hit google's api to
    # get service account information and parse email
    raise NotImplementedError('Functionality not yet available...')


# TODO this should be in cirrus rather than fence...
def get_google_project_from_service_account_email(account_id):
    # parse email to get project id_
    raise NotImplementedError('Functionality not yet available...')
