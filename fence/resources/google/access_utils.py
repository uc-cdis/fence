"""
Utilities for determine access and validity for service account
registration.
"""
import flask
from urllib import unquote

from google.cloud.exceptions import GoogleCloudError
from flask_sqlalchemy_session import current_session

from cirrus.google_cloud.iam import GooglePolicyMember
from cirrus import GoogleCloudManager
from cirrus.google_cloud.errors import GoogleAPIError
from cirrus.google_cloud.iam import GooglePolicy
from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
)

import fence
from fence.errors import NotFound
from fence.models import (
    AccessPrivilege,
    UserServiceAccount,
    ServiceAccountAccessPrivilege,
    ServiceAccountToGoogleBucketAccessGroup,
)
from fence.resources.google.utils import (
    get_db_session,
    get_user_ids_from_google_members,
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
    except GoogleCloudError as exc:
        flask.current_app.logger.debug((
            'Could not determine if Google project (id: {}) has parent org'
            'due to error (Details: {})'.
            format(project_id, exc)
        ))
        return False


def google_project_has_valid_membership(project_id):
    """
    Checks if a google project only has members of type
    USER or SERVICE_ACCOUNT and that the project's members
    exist in fence's db

    Args:
        google_project(GoogleCloudManager): google project to check members of

    Return:
        Bool: True iff project members are only users and/or service accounts
    """
    valid = True
    try:
        with GoogleCloudManager(project_id) as prj:
            members = prj.get_project_membership()
            for member in members:
                if not(member.member_type == GooglePolicyMember.SERVICE_ACCOUNT or
                        member.member_type == GooglePolicyMember.USER):
                    valid = False

            # ensure that all the members on the project exist
            # in our db
            member_emails = [
                member.email_id
                for member in members
            ]
            try:
                get_user_ids_from_google_members(member_emails)
            except NotFound:
                valid = False

    except GoogleCloudError as exc:
        flask.current_app.logger.debug((
            'validity of Google Project (id: {}) membership '
            'determined False due to error. Details: {}').
            format(project_id, exc))
        valid = False

    return valid


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
    except GoogleCloudError as exc:
        flask.current_app.logger.debug((
            'validity of Google service account {} (google project: {}) type '
            'determined False due to error. Details: {}').
            format(account_id, project_id, exc))
        return False


def service_account_has_external_access(service_account, google_project_id):
    """
    Checks if service account has external access or not.

    Args:
        service_account(str): service account

    Returns:
        bool: whether or not the service account has external access
    """
    with GoogleCloudManager(google_project_id) as g_mgr:
        response = g_mgr.get_service_account_policy(service_account)
        if response.status_code != 200:
            raise GoogleAPIError('Unable to get IAM policy for service account {}\n{}.'
                                .format(service_account, response.json()))
        json_obj = response.json()
        # In the case that a service account does not have any role, Google API
        # returns a json object without bindings key
        if 'bindings' in json_obj:
            policy = GooglePolicy.from_json(json_obj)
            if policy.roles:
                return True
        if g_mgr.get_service_account_keys_info(service_account):
            return True
    return False


def is_service_account_from_google_project(service_account, project_id):
    """
    Checks if service account is among project's service acounts

    Args:
        service_account(str): uniqueId of service account
        project_id(str): uniqueId of Google Cloud Project

    Return:
        Bool: True iff the given service_account is from the
        given Google Project
    """
    try:
        service_accounts = (
            acc.get('uniqueId') for acc in
            GoogleCloudManager(project_id).get_all_service_accounts()
        )
        return service_account in service_accounts
    except GoogleCloudError as exc:
        flask.current_app.logger.debug((
            'Could not determine if service account (id: {} is from project'
            ' (id: {}) due to error. Details: {}').
            format(service_account, project_id, exc))
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

            if any(service_account_has_external_access(acc.get('email'), project_id)
                   for acc in service_accounts):
                return False

            members = prj.get_project_membership()

    except GoogleCloudError as exc:
        flask.current_app.logger.debug((
            "Could not determine validity of service accounts"
            "for project (id: {}) due to error. Details: {}".
            format(project_id,exc)
        ))
        return False

    sa_members = [GooglePolicyMember(
        GooglePolicyMember.SERVICE_ACCOUNT,
        sa.get('email'))
        for sa in service_accounts]

    for mem in members:
        if mem.member_type == GooglePolicyMember.SERVICE_ACCOUNT:
            if mem not in sa_members:
                return False

    return True


def get_service_account_email(id_from_url):
    """
    Return email given it in id form from the url.
    """
    return unquote(id_from_url)


def get_google_project_from_service_account_email(service_account_email):
    """
    Parse email to get google project id
    """
    words = service_account_email.split('@')
    return words[1].split('.')[0]


def _force_remove_service_account_from_access_db(service_account_email, db=None):
    """
    Remove the access of service account from db.

    Args:
        service_account_email (str): service account email

    Returns:
        None

    Restrictions:
        service account has to exist in db

    """

    session = get_db_session(db)

    service_account = (
        session.query(UserServiceAccount).
        filter_by(email=service_account_email).first()
    )

    access_groups = service_account.to_access_groups

    for bucket_access_group in access_groups:
        sa_to_group = (
            session.query(ServiceAccountToGoogleBucketAccessGroup)
            .filter_by(
                service_account_id=service_account.id,
                access_group_id=bucket_access_group.id
            )
            .first()
        )
        session.delete(sa_to_group)
        session.commit()

    # delete all access privileges
    access_privileges = (
        session.query(ServiceAccountAccessPrivilege)
        .filter_by(service_account_id=service_account.id)
        .all()
    )

    for access in access_privileges:
        session.delete(access)
    session.commit()


def force_remove_service_account_from_access(
        service_account_email, google_project_id, db=None):
    """
    loop through ServiceAccountToBucket
    remove from google group
    delete entries from db

    Args:
        service_account_email (str): service account email
        google_project_id (str): google project id
        db (None, str): Optional db connection string

    Returns:
        None
    """

    session = get_db_session(db)

    service_account = (
        session.query(UserServiceAccount).
        filter_by(email=service_account_email).first()
    )

    if not service_account:
        raise fence.errors.NotFound('{} does not exist in DB'
                                   .format(service_account_email))
    access_groups = service_account.to_access_groups
    for bucket_access_group in access_groups:
        try:
            with GoogleCloudManager(google_project_id) as g_manager:
                g_manager.remove_member_from_group(
                    member_email=service_account.email,
                    group_id=bucket_access_group.access_group_id
                )
        except Exception as exc:
            raise GoogleAPIError('Can not remove memeber {} from access group. {}'
                                 .format(service_account.email, exc))

    _force_remove_service_account_from_access_db(service_account_email, db)

