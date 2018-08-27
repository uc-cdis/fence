"""
Utilities for determine access and validity for service account
registration.
"""
import time
import flask
from urllib import unquote

from flask_sqlalchemy_session import current_session

from cirrus.google_cloud.iam import GooglePolicyMember

from cirrus.google_cloud.errors import GoogleAPIError
from cirrus.google_cloud.iam import GooglePolicy
from cirrus import GoogleCloudManager
from cirrus.google_cloud import (
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
)

import fence
from fence.errors import NotFound, NotSupported
from fence.models import (
    User,
    Project,
    AccessPrivilege,
    UserGoogleAccount,
    UserServiceAccount,
    ServiceAccountAccessPrivilege,
    ServiceAccountToGoogleBucketAccessGroup,
)
from fence.resources.google.utils import (
    get_db_session,
    get_users_from_google_members,
    get_monitoring_service_account_email,
)

ALLOWED_SERVICE_ACCOUNT_TYPES = [
    COMPUTE_ENGINE_DEFAULT_SERVICE_ACCOUNT,
    USER_MANAGED_SERVICE_ACCOUNT,
]


def can_access_google_project(google_project_id):
    """
    Whether or not fence can access the given google project.

    Args:
        google_project_id (str): Google project ID

    Returns:
        bool: Whether or not fence can access the given google project.
    """
    try:
        with GoogleCloudManager(google_project_id, use_default=False) as g_mgr:
            response = g_mgr.get_project_info()
            project_id = response.get('projectId')

            if not project_id:
                return False
    except Exception:
        return False

    return True


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
        with GoogleCloudManager(project_id, use_default=False) as prj:
            return prj.has_parent_organization()
    except Exception as exc:
        flask.current_app.logger.debug((
            'Could not determine if Google project (id: {}) has parent org'
            'due to error (Details: {})'.
            format(project_id, exc)
        ))
        return False


def get_google_project_valid_users_and_service_accounts(project_id):
    """
    Gets google project members of type
    USER or SERVICE_ACCOUNT and raises an error if it finds a member
    that isn't one of those types.

    Args:
        project_id (str): Google project ID

    Return:
        List[cirrus.google_cloud.iam.GooglePolicyMember]: Members on the
            google project

    Raises:
        NotSupported: Member is invalid type
    """
    try:
        with GoogleCloudManager(project_id, use_default=False) as prj:
            members = prj.get_project_membership(project_id)
            for member in members:
                if not(member.member_type == GooglePolicyMember.SERVICE_ACCOUNT or
                        member.member_type == GooglePolicyMember.USER):
                    raise NotSupported(
                        'Member {} has invalid type: {}'.format(
                            member.email_id, member.member_type)
                    )
            users = [
                member for member in members
                if member.member_type == GooglePolicyMember.USER
            ]
            service_accounts = [
                member for member in members
                if member.member_type == GooglePolicyMember.SERVICE_ACCOUNT
            ]
            return users, service_accounts
    except Exception as exc:
        flask.current_app.logger.debug((
            'validity of Google Project (id: {}) members '
            'could not complete. Details: {}')
            .format(project_id, exc))
        raise


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
        with GoogleCloudManager(project_id, use_default=False) as g_mgr:
            return (g_mgr.
                    get_service_account_type(account_id)
                    in ALLOWED_SERVICE_ACCOUNT_TYPES)
    except Exception as exc:
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
    with GoogleCloudManager(google_project_id, use_default=False) as g_mgr:
        response = g_mgr.get_service_account_policy(service_account)
        if response.status_code != 200:
            flask.current_app.logger.debug(
                'Unable to get IAM policy for service account {}\n{}.'
                .format(service_account, response.json()))
            # if there is an exception, assume it has external access
            return True

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


def is_service_account_from_google_project(service_account_email, project_id):
    """
    Checks if service account is among project's service acounts

    Args:
        service_account_email(str): service account email
        project_id(str): uniqueId of Google Cloud Project

    Return:
        Bool: True iff the given service_account_email is from the
        given Google Project
    """
    try:
        sa_google_project = (
            get_google_project_from_service_account_email(
                service_account_email)
        )
        return sa_google_project == project_id
    except Exception as exc:
        flask.current_app.logger.debug((
            'Could not determine if service account (id: {} is from project'
            ' (id: {}) due to error. Details: {}').
            format(service_account_email, project_id, exc))
        return False


def is_user_member_of_all_google_projects(
        user_id, google_project_ids, db=None):
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
    session = get_db_session(db)
    user = (
        session.query(User)
        .filter_by(id=user_id)
        .first()
    )
    if not user:
        flask.current_app.logger.debug((
            'Could not determine if user (id: {} is from projects:'
            ' {} due to error. User does not exist...').
            format(user_id, google_project_ids))
        return False

    linked_google_account = (
        current_session.query(UserGoogleAccount)
        .filter(UserGoogleAccount.user_id == user_id).first()
    )

    try:
        for google_project_id in google_project_ids:
            with GoogleCloudManager(google_project_id, use_default=False) as g_mgr:
                member_emails = [
                    member.email_id.lower()
                    for member in g_mgr.get_project_membership(google_project_id)
                ]
                # first check if user.email is in project, then linked account
                if not (user.email and user.email in member_emails):
                    if not (linked_google_account
                            and linked_google_account.email in member_emails
                            ):
                        # no user email is in project
                        return False
    except Exception as exc:
        flask.current_app.logger.debug((
            'Could not determine if user (id: {} is from projects:'
            ' {} due to error. Details: {}')
            .format(user_id, google_project_ids, exc))
        return False

    return True


def do_all_users_have_access_to_project(users, project_id):
    # users will be list of fence.model.User's
    # check if all users has access to a project with project_id
    for user in users:
        access_privilege = (
            current_session
            .query(AccessPrivilege)
            .filter(AccessPrivilege.user_id == user.id)
            .filter(AccessPrivilege.project_id == project_id)
        ).first()

        if not access_privilege:
            return False

    return True


def patch_user_service_account(
        google_project_id, service_account_email, project_access, db=None):
    """
    Update user service account which includes
    - Add and remove project access and bucket groups to/from fence db
    - Add and remove access memebers to/from google access group

    Args:
        google_project_id (str): google project id
        service_account_email (str): service account email
        project_access (List(str)): list of projects

    Returns:
        None
    """
    session = get_db_session(db)
    service_account = (
            session.query(UserServiceAccount)
            .filter_by(email=service_account_email)
            .first()
    )
    if not service_account:
        raise fence.errors.NotFound(
                '{} does not exist in DB'
                .format(service_account_email))

    accessed_project_ids = {
        ap.project_id for ap in (
            session
            .query(ServiceAccountAccessPrivilege)
            .filter_by(service_account_id=service_account.id)
            .all()
        )
    }

    granting_project_ids = get_project_ids_from_project_auth_ids(
        session, project_access)

    to_add = set.difference(granting_project_ids, accessed_project_ids)
    to_delete = set.difference(accessed_project_ids, granting_project_ids)

    _revoke_user_service_account_from_google(
        session, to_delete, google_project_id, service_account)
    add_user_service_account_to_google(
        session, to_add, google_project_id, service_account)
    _revoke_user_service_account_from_db(
        session, to_delete, service_account)
    add_user_service_account_to_db(
        session, to_add, service_account)


def get_project_ids_from_project_auth_ids(session, auth_ids):
    """
    Return the Project.id's for the given list of Project.auth_id's

    Args:
        auth_ids (set(str)): list of project auth ids
    """
    project_ids = set()
    for project_auth_id in auth_ids:
        project = (
            session.query(Project)
            .filter_by(auth_id=project_auth_id)
            .first()
        )
        if not project:
            raise fence.errors.NotFound(
                    'There is no {} in Fence db'
                    .format(project_auth_id))
        project_ids.add(project.id)
    return project_ids


def _force_remove_service_account_from_access_db(
        service_account_email, db=None):
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
        session
        .query(UserServiceAccount)
        .filter_by(email=service_account_email)
        .first()
    )

    access_groups = get_google_access_groups_for_service_account(
        service_account)

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
        raise fence.errors.NotFound(
                '{} does not exist in DB'
                .format(service_account_email)
            )

    access_groups = get_google_access_groups_for_service_account(
        service_account)

    for bucket_access_group in access_groups:
        try:
            with GoogleCloudManager(google_project_id, use_default=False) as g_manager:
                g_manager.remove_member_from_group(
                    member_email=service_account.email,
                    group_id=bucket_access_group.email
                )
        except Exception as exc:
            raise GoogleAPIError(
                    'Can not remove memeber {} from access group. {}'
                    .format(service_account.email, exc))

    _force_remove_service_account_from_access_db(service_account_email, db)


def _revoke_user_service_account_from_google(
        session, to_delete_project_ids, google_project_id, service_account):
    """
    revoke service account from google access group

    Args:
        session(current_session): db session
        to_delete_project_ids (List(str)): list of project ids
        google_project_id (str): google project id
        service_account (UserServiceAccount): user service account

    Returns:
        None

    """
    for project_id in to_delete_project_ids:
        access_groups = _get_google_access_groups(session, project_id)

        for access_group in access_groups:
            try:
                # TODO: Need to remove outer try/catch after major refactor
                with GoogleCloudManager(google_project_id, use_default=False) as g_manager:
                    if not g_manager.remove_member_from_group(
                            member_email=service_account.email,
                            group_id=access_group.email):

                        flask.current_app.logger.debug(
                                'Removed {} from google group {}'
                                .format(service_account.email, access_group.email))
                    else:
                        raise GoogleAPIError(
                                'Can not remove {} from group {}')
            except Exception as exc:
                raise GoogleAPIError(
                        'Can not remove {} from group {}. Detail {}'
                        .format(service_account.email, access_group.email, exc))


def add_user_service_account_to_google(
        session, to_add_project_ids, google_project_id, service_account):
    """
    Add service account to google access groups

    Args:
        session(current_session): db session
        to_add_project_ids (List(id)): list of project ids
        google_project_id (str): google project id
        service_account (UserServiceAccount): user service account

    """
    for project_id in to_add_project_ids:
        access_groups = _get_google_access_groups(session, project_id)
        for access_group in access_groups:
            try:
                # TODO: Need to remove try/catch after major refactor
                with GoogleCloudManager(google_project_id, use_default=False) as g_manager:
                    response = g_manager.add_member_to_group(
                        member_email=service_account.email,
                        group_id=access_group.email
                    )
                    if response.get('id', None):
                        flask.current_app.logger.debug(
                            'Successfully add member {} to google group {}.'
                            .format(service_account.email, access_group.email))
                    else:
                        raise GoogleAPIError(
                            'Can not add {} to group {}'
                            .format(service_account.email, access_group.email))

            except Exception as exc:
                raise GoogleAPIError(
                        'Can not add {} to group {}. Detail {}'
                        .format(service_account.email, access_group.email, exc)
                    )


def _revoke_user_service_account_from_db(
        session, to_delete_project_ids, service_account):
    """
    Remove service account from GoogleBucketAccessGroup

    Args:
        session(current_session): db session
        to_delete_ids(List(int)): List of bucket ids
        service_account_email(str): service account email

    Returns:
        None
    """
    for project_id in to_delete_project_ids:
        access_project = (
            session
            .query(ServiceAccountAccessPrivilege)
            .filter_by(project_id=project_id, service_account_id=service_account.id)
            .first()
        )
        session.delete(access_project)

        access_groups = _get_google_access_groups(session, project_id)
        for access_group in access_groups:
            account_access_bucket_group = (
                session
                .query(ServiceAccountToGoogleBucketAccessGroup)
                .filter_by(service_account_id=service_account.id, access_group_id=access_group.id)
                .first()
            )
            if account_access_bucket_group:
                session.delete(account_access_bucket_group)

    session.commit()


def add_user_service_account_to_db(
        session, to_add_project_ids, service_account):
    """
    Add user service account to service account
    access privilege and service account bucket access group

    Args:
        sess(current_session): db session
        to_add_project_ids(List(int)): List of project id
        service_account(UserServiceAccount): user service account

    Returns:
        None

    Contrains:
        The service account is not in DB yet

    """
    for project_id in to_add_project_ids:
        session.add(
                ServiceAccountAccessPrivilege(
                        project_id=project_id,
                        service_account_id=service_account.id
                )
        )

        access_groups = _get_google_access_groups(session, project_id)

        # use configured time or 7 days
        expiration_time = (
            int(time.time())
            + flask.current_app.config.get(
                'GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN',
                604800)
        )
        for access_group in access_groups:
            sa_to_group = ServiceAccountToGoogleBucketAccessGroup(
                service_account_id=service_account.id,
                expires=expiration_time,
                access_group_id=access_group.id
            )
            session.add(sa_to_group)

    session.commit()


def get_google_project_from_service_account_email(service_account_email):
    """
    Parse email to get google project id
    """
    words = service_account_email.split('@')
    return words[1].split('.')[0]


def get_service_account_email(id_from_url):
    """
    Return email given it in id form from the url.
    """
    return unquote(id_from_url)


def _get_google_access_groups(session, project_id):
    """
    Get google access groups

    Args:
        session(current_session): db session
        project_id (int): project id in db

    Returns:
        List(GoogleBucketAccessGroup)
    """
    access_groups = []
    project = (
        session.query(Project).filter_by(id=project_id).first()
    )

    for bucket in project.buckets:
        groups = bucket.google_bucket_access_groups
        access_groups.extend(groups)

    return access_groups


def extend_service_account_access(service_account_email, db=None):
    """
    Extend the Google service accounts access to data by extending the
    expiration time for each of the Google Bucket Access Groups it's in.

    WARNING: This does NOT do any AuthZ, do before this.

    Args:
        service_account_email (str): service account email
    """
    session = get_db_session(db)

    service_account = (
        session.query(UserServiceAccount).
        filter_by(email=service_account_email).first()
    )

    if service_account:
        bucket_access_groups = get_google_access_groups_for_service_account(
            service_account)

        # use configured time or 7 days
        expiration_time = (
            int(time.time())
            + flask.current_app.config.get(
                'GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN',
                604800)
        )
        for access_group in bucket_access_groups:
            bucket_access = (
                session
                .query(ServiceAccountToGoogleBucketAccessGroup)
                .filter_by(
                    service_account_id=service_account.id,
                    access_group_id=access_group.id
                )
                .first()
            )
            if not bucket_access:
                bucket_access = ServiceAccountToGoogleBucketAccessGroup(
                    service_account_id=service_account.id,
                    access_group_id=access_group.id,
                    expires=expiration_time
                )
                session.add(bucket_access)

            bucket_access.expires = expiration_time

        session.commit()


def get_current_service_account_project_access(service_account_email, db=None):
    """
    Return a list of project auth_ids the service account currently has
    access to.

    Args:
        service_account_email (str): service account email

    Returns:
        List[str]: List of Project.auth_ids

    Raises:
        NotFound: if service account doesn't exist
    """
    session = get_db_session(db)

    service_account = (
        session.query(UserServiceAccount)
        .filter_by(email=service_account_email).first()
    )

    if not service_account:
        raise NotFound(
            'No service account {} exists.'.format(service_account_email))

    project_access = [
        access_privilege.project.auth_id
        for access_privilege in service_account.access_privileges
    ]

    return project_access


def get_google_access_groups_for_service_account(service_account):
    """
    Return list of fence.models.GoogleBucketAccessGroup objects that the
    given service account should have access to based on it's access
    privileges.

    Args:
        service_account (fence.models.UserServiceAccount): service account
            object

    Returns:
        List[fence.models.GoogleBucketAccessGroup]: list of google bucket
            access groups the service account should have access to
    """
    return [
        group
        for access_privilege in service_account.access_privileges
        for bucket in access_privilege.project.buckets
        for group in bucket.google_bucket_access_groups
    ]


def get_project_from_auth_id(project_auth_id, db=None):
    """
    Return a Project given a Project.auth_id (or None if it doesnt exist.)

    Args:
        project_auth_id (str): Project.auth_id

    Returns:
        int: Project
    """
    session = get_db_session(db)

    project = (
        session.query(Project)
        .filter_by(auth_id=project_auth_id).first()
    )

    return project


def remove_white_listed_service_account_ids(service_account_ids):
    """
    Remove any service account emails that should be ignored when
    determining validitity.

    Args:
        service_account_ids (List[str]): Service account emails

    Returns:
        List[str]: Service account emails
    """
    monitoring_service_account = get_monitoring_service_account_email()
    if monitoring_service_account in service_account_ids:
        service_account_ids.remove(monitoring_service_account)

    if 'WHITE_LISTED_SERVICE_ACCOUNT_EMAILS' in flask.current_app.config:
        for email in (flask.current_app.config
                      .get('WHITE_LISTED_SERVICE_ACCOUNT_EMAILS', [])):
                if email in service_account_ids:
                    service_account_ids.remove(email)

    return service_account_ids


def force_delete_service_account(service_account_email, db=None):
    """
    Delete from our db the given user service account by email.

    Args:
        service_account_email (str): user service account email
    """
    session = get_db_session(db)

    sa = (
        session.query(UserServiceAccount)
        .filter_by(email=service_account_email).first()
    )

    if sa:
        session.delete(sa)
        session.commit()


def force_add_service_accounts_to_access(
        service_account_emails, google_project_id, project_access, db=None):
    """
    service_account_emails(list(str)): list of account emails
    google_project_id(str):  google project id
    project_access(list(str)): list of projects
    """
    session = get_db_session(db)

    with GoogleCloudManager(google_project_id) as google_project:
        for service_account_email in service_account_emails:
            g_service_account = google_project.get_service_account(
                service_account_email)
            sa = (
                session.query(UserServiceAccount)
                .filter_by(email=service_account_email).first()
            )
            if not sa:
                sa = UserServiceAccount(
                    google_unique_id=g_service_account.get('uniqueId'),
                    email=service_account_email,
                    google_project_id=google_project_id
                )
                session.add(sa)
                session.commit()

            project_ids = set()
            for project in project_access:
                project_db = (
                    session.query(Project)
                    .filter_by(auth_id=project).first()
                )
                if project_db:
                    project_ids.add(project_db.id)

            add_user_service_account_to_db(
                session, project_ids, sa)

            add_user_service_account_to_google(
                session, project_ids, google_project_id, sa)