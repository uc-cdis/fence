"""
Utilities for determine access and validity for service account
registration.
"""
import flask

from flask_sqlalchemy_session import current_session
from fence.models import AccessPrivilege
from cirrus.google_cloud.iam import GooglePolicyMember

from cirrus import GoogleCloudManager
from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
)

ALLOWED_SERVICE_ACCOUNT_TYPES = [
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
]

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


def google_project_has_parent_org(project_id):
    """
    Checks if google project has parent org. Wraps
    GoogleCloudManager.has_parent_organization()

    Args:
        project_id(str): unique id for project

    Returns:
        Bool: True iff google project has a parent
        organization
    """
    try:
        with GoogleCloudManager(project_id) as prj:
            return prj.has_parent_organization()
    except Exception as exc:
        flask.current_app.logger.debug((
            'Could not determine if Google project (id: {}) has parent org'
            'due to error (Details: {})'.
            format(project_id, exc)
        ))
        return False


def google_project_has_valid_membership(project_id):
    """
    Checks if a google project only has members of type
    USER or SERVICE_ACCOUNT

    Args:
        google_project(GoogleCloudManager): google project to check members of

    Return:
        Bool: True iff project members are only users and/or service accounts
    """

    try:
        with GoogleCloudManager(project_id) as prj:
            members = prj.get_project_membership()
            for member in members:
                if not(member.member_type == GooglePolicyMember.SERVICE_ACCOUNT or
                        member.member_type == GooglePolicyMember.USER):
                    return False

            return True

    except Exception as exc:
        flask.current_app.logger.debug((
            'validity of Google Project (id: {}) membership '
            'determined False due to error. Details: {}').
            format(project_id, exc))
        return False


def is_valid_service_account_type(project_id, account_id):
    """
    Checks service account type against allowed service account types
    for service account registration

    Args:
        project_id(str): project identifier for project associated
            with service account
        account_id(str): account identifier to check valid type

    Returns:
        Bool: True if service acocunt type is allowed as defined
        in ALLOWED_SERVICE_ACCOUNT_TYPES
    """
    try:
        with GoogleCloudManager(project_id) as g_mgr:
            return (g_mgr.
                    get_service_account_type(account_id)
                    in ALLOWED_SERVICE_ACCOUNT_TYPES)
    except Exception as exc:
        flask.current_app.logger.debug((
            'validity of Google service account {} (google project: {}) type '
            'determined False due to error. Details: {}').
            format(account_id, project_id, exc))
        return False


def service_account_has_external_access(service_account):
    raise NotImplementedError('Functionality not yet available...')


def is_service_account_from_google_project(service_account, project_id):
    return service_account in GoogleCloudManager(project_id).get_all_service_accounts()


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


def google_project_has_valid_service_accounts(project_id):
    """
    Checks if all service accounts in a project do not
    have external access. Also checks that all service
    account members in IAM Policy are from the given
    project.
    Args:
        project_id(str): unique id of project
    ReturnsL
        Bool: True iff all service accounts are valid
    """
    try:
        with GoogleCloudManager(project_id) as prj:
            service_accounts = prj.get_all_service_accounts()

            for acc in service_accounts:
                if service_account_has_external_access(acc):
                    return False

            members = prj.get_project_membership()

            for mem in members:
                if mem.member_type == GooglePolicyMember.SERVICE_ACCOUNT:
                    if mem not in service_accounts:
                        return False

            return True
    except Exception as exc:
        flask.current_app.logger.debug((
            "Could not determine validity of service accounts"
            "for project (id: {}) due to error. Details: {}".
            format(project_id,exc)
        ))
        return False



# TODO this should be in cirrus rather than fence...
def get_service_account_email(account_id):
    # first check if the account_id is an email, if not, hit google's api to
    # get service account information and parse email
    raise NotImplementedError('Functionality not yet available...')


# TODO this should be in cirrus rather than fence...
def get_google_project_from_service_account_email(account_id):
    # parse email to get project id_
    raise NotImplementedError('Functionality not yet available...')
