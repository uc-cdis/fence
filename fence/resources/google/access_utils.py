"""
Utilities for determine access and validity for service account
registration.
"""
import time
import flask
import time
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
    Project,
    Bucket,
    GoogleBucketAccessGroup,
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


def service_account_has_external_access(service_account):
    """
    Checks if service account has external access or not.

    Args:
        service_account(str): service account

    Returns:
        bool: whether or not the service account has external access
    """
    with GoogleCloudManager() as g_mgr:
        response = g_mgr.get_service_account_policy(service_account)
        if response.status_code != 200:
            raise GoogleAPIError(
                'Unable to get IAM policy for service account {}\n{}.'
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

            if any(service_account_has_external_access(acc.get('email'))
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


def _get_google_access_groups(session, project_id):
    """
    Get google access groups

    Args:
        sess(current_session): db session
        project_id (str): project id in db

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


def _revoke_user_service_account_from_google(session, to_delete_project_ids, service_account):
    """
    revoke service account from google access group

    Args:
        sess(current_session): db session
        to_delete_project_ids (List(str)): list of project ids
        service_account (UserServiceAccount): user service account

    Returns:
        None

    """
    for project_id in to_delete_project_ids:
        access_groups = _get_google_access_groups(session, project_id)

        for access_group in access_groups:
            try:
                with GoogleCloudManager() as g_manager:
                    g_manager.remove_member_from_group(
                        member_email=service_account.email,
                        group_id=access_group.email
                    )
            except Exception as exc:
                raise GoogleAPIError('Can not remove {} from group {}. Detail {}'
                                     .format(service_account.email, access_group.email, exc))


def _add_user_service_account_to_google(session, to_add_project_ids, service_account):
    """
    Add service account to google access groups

    Args:
        sess(current_session): db session
        to_add_project_ids (List(str)): list of project ids
        service_account (UserServiceAccount): user service account

    """
    for project_id in to_add_project_ids:
        access_groups = _get_google_access_groups(session, project_id)

        for access_group in access_groups:
            try:
                with GoogleCloudManager() as g_manager:
                    g_manager.add_member_to_group(
                        member_email=service_account.email,
                        group_id=access_group.email
                    )
            except Exception as exc:
                raise GoogleAPIError('Can not add {} to group {}. Detail {}'
                                     .format(service_account.email, access_group.email, exc))


def _revoke_user_service_account_from_db(session, to_delete_project_ids, service_account):
    """
    Remove service account from GoogleBucketAccessGroup

    Args:
        sess(current_session): db session
        to_delete_ids(List(int)): List of bucket ids
        service_account_email(str): service account email

    Returns:
        None
    """
    for project_id in to_delete_project_ids:
        access_project = (
            session.
            query(ServiceAccountAccessPrivilege).
            filter_by(project_id=project_id, service_account_id=service_account.id).
            first()
        )
        session.delete(access_project)

        access_groups = _get_google_access_groups(session, project_id)
        for access_group in access_groups:
            account_access_bucket_group = (
                session.
                query(ServiceAccountToGoogleBucketAccessGroup).
                filter_by(service_account_id=service_account.id, access_group_id=access_group.id).
                first()
            )
            session.delete(account_access_bucket_group)

    session.commit()


def _add_user_service_account_to_db(
        session, to_add_project_ids, service_account):
    """
    Add user service account to service account
    access privilege and service account bucket access group

    Args:
        sess(current_session): db session
        to_add_project_ids(List(str)): List of project id
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
            time.time()
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
            session.query(UserServiceAccount).
            filter_by(email=service_account_email).first()
    )
    if not service_account:
        raise fence.errors.NotFound('{} does not exist in DB'
                                    .format(service_account_email))
    accessed_projects = (
        session.query(ServiceAccountAccessPrivilege).
        filter_by(service_account_id=service_account.id).all()
    )
    accessed_project_ids = {ap.project_id for ap in accessed_projects}

    granting_project_ids = set()
    for project_auth_id in project_access:
        project = (
            session.query(Project).
            filter_by(auth_id=project_auth_id).
            first()
        )
        if not project:
            raise fence.errors.NotFound('There is no {} in Fence db'
                                        .format(project_auth_id))
        granting_project_ids.add(project.id)

    to_add = set.difference(granting_project_ids, accessed_project_ids)
    to_delete = set.difference(accessed_project_ids, granting_project_ids)

    _revoke_user_service_account_from_google(session, to_delete, service_account)
    _add_user_service_account_to_google(session, to_add, service_account)
    _revoke_user_service_account_from_db(session, to_delete, service_account)
    _add_user_service_account_to_db(session, to_add, service_account)


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
        raise fence.errors.NotFound(
            '{} does not exist in DB'.format(service_account_email))
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
        bucket_access_groups = _get_google_access_groups_for_service_account(
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


def _get_google_access_groups_for_service_account(service_account):
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
