"""
Utilities for determine access and validity for service account
registration.
"""
import time
import flask
from urllib.parse import unquote

from cirrus.google_cloud.iam import GooglePolicyMember

from cirrus.google_cloud.errors import GoogleAPIError
from cirrus.google_cloud.iam import GooglePolicy
from cirrus import GoogleCloudManager

import fence
from cdislogging import get_logger

from fence.config import config
from fence.errors import NotFound, NotSupported, UserError
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
    is_google_managed_service_account,
)
from fence.utils import get_valid_expiration_from_request

logger = get_logger(__name__)


def bulk_update_google_groups(google_bulk_mapping):
    """
    Update Google Groups based on mapping provided from Group -> Users.

    Args:
        google_bulk_mapping (dict): {"googlegroup@google.com": ["member1", "member2"]}
    """
    google_project_id = (
        config["STORAGE_CREDENTIALS"].get("google", {}).get("google_project_id")
    )
    with GoogleCloudManager(google_project_id) as gcm:
        for group, expected_members in google_bulk_mapping.items():
            expected_members = set(expected_members)
            logger.debug(f"Starting diff for group {group}...")

            # get members list from google
            google_members = set(
                member.get("email") for member in gcm.get_group_members(group)
            )
            logger.debug(f"Google membership for {group}: {google_members}")
            logger.debug(f"Expected membership for {group}: {expected_members}")

            # diff between expected group membership and actual membership
            to_delete = set.difference(google_members, expected_members)
            to_add = set.difference(expected_members, google_members)
            no_update = set.intersection(google_members, expected_members)

            logger.info(f"All already in group {group}: {no_update}")

            # do add
            for member_email in to_add:
                logger.info(f"Adding to group {group}: {member_email}")
                gcm.add_member_to_group(member_email, group)

            # do remove
            for member_email in to_delete:
                logger.info(f"Removing from group {group}: {member_email}")
                gcm.remove_member_from_group(member_email, group)


def get_google_project_number(google_project_id, google_cloud_manager):
    """
    Return a project's "projectNumber" which uniquely identifies it.
    This will only be successful if fence can access info about the given google project
    and the necessary Google APIs are enabled.

    Args:
        google_project_id (str): Google project ID
        google_cloud_manager (GoogleCloudManager): cloud manager instance

    Returns:
        str: string repsentation of an int64 uniquely identifying a Google project
    """
    try:
        response = google_cloud_manager.get_project_info()
        return response.get("projectNumber")
    except Exception as exc:
        logger.error(
            "Could not determine google project number for Project"
            "ID: {} due to error. (Details : {})".format(google_project_id, exc)
        )
        return None


def get_google_project_membership(project_id, google_cloud_manager):
    """
    Returns GCM get_project_membership() result, which is a list of all
    members on the projects IAM

    Args:
        project_id(str): unique id for project
        google_cloud_manager(GoogleCloudManager): cloud manager instance

    Returns
        List(GooglePolicyMember): list of members on project's IAM
    """

    return google_cloud_manager.get_project_membership(project_id)


def get_google_project_parent_org(google_cloud_manager):
    """
    Checks if google project has parent org. Wraps
    GoogleCloudManager.get_project_organization()

    Args:
        google_cloud_manager(GoogleCloudManager): cloud manager instance

    Returns:
        str: The Google projects parent organization name or None if it does't have one
    """
    try:
        return google_cloud_manager.get_project_organization()
    except Exception as exc:
        logger.error(
            "Could not determine if Google project (id: {}) has parent org"
            "due to error (Details: {})".format(
                getattr(google_cloud_manager, "project_id", "unknown"), exc
            )
        )
        return None


def get_google_project_valid_users_and_service_accounts(
    project_id, google_cloud_manager, membership=None
):
    """
    Gets google project members of type
    USER or SERVICE_ACCOUNT and raises an error if it finds a member
    that isn't one of those types.

    Args:
        project_id (str): Google project ID
        google_cloud_manager(GoogleCloudManager): cloud manager instance
        membership (List(GooglePolicyMember): pre-calculated list of members,
            Will make call to Google API if membership is None

    Return:
        List[cirrus.google_cloud.iam.GooglePolicyMember]: Members on the
            google project

    Raises:
        NotSupported: Member is invalid type
    """
    try:
        members = membership or google_cloud_manager.get_project_membership(project_id)
        for member in members:
            if not (
                member.member_type == GooglePolicyMember.SERVICE_ACCOUNT
                or member.member_type == GooglePolicyMember.USER
            ):
                raise NotSupported(
                    "Member {} has invalid type: {}".format(
                        member.email_id, member.member_type
                    )
                )
        users = [
            member
            for member in members
            if member.member_type == GooglePolicyMember.USER
        ]
        service_accounts = [
            member
            for member in members
            if member.member_type == GooglePolicyMember.SERVICE_ACCOUNT
        ]
        return users, service_accounts
    except Exception as exc:
        logger.error(
            "validity of Google Project (id: {}) members "
            "could not complete. Details: {}".format(project_id, exc)
        )

        raise


def is_valid_service_account_type(account_id, google_cloud_manager):
    """
    Checks service account type against allowed service account types
    for service account registration

    Args:
        account_id(str): account identifier to check valid type
        google_cloud_manager(GoogleCloudManager): cloud manager instance

    Returns:
        Bool: True if service acocunt type is allowed as defined
        in ALLOWED_USER_SERVICE_ACCOUNT_DOMAINS
    """
    try:
        sa_type = google_cloud_manager.get_service_account_type(account_id)
        return sa_type in config["ALLOWED_USER_SERVICE_ACCOUNT_DOMAINS"]
    except Exception as exc:
        logger.error(
            "validity of Google service account {} (google project: {}) type "
            "determined False due to error. Details: {}".format(
                account_id, google_cloud_manager.project_id, exc
            )
        )


def service_account_has_external_access(
    service_account, google_cloud_manager, policy=None
):
    """
    Checks if service account has external access or not.

    Args:
        service_account(str): service account
        google_project_id(str): google project id
        policy(dict): response from previous call to get_service_account_policy

    Returns:
        bool: whether or not the service account has external access
    """
    response = policy or google_cloud_manager.get_service_account_policy(
        service_account
    )
    if response.status_code != 200:
        logger.error(
            "Unable to get IAM policy for service account {}\n{}.".format(
                service_account, response.json()
            )
        )
        # if there is an exception, assume it has external access
        return True

    json_obj = response.json()
    # In the case that a service account does not have any role, Google API
    # returns a json object without bindings key
    if "bindings" in json_obj:
        policy = GooglePolicy.from_json(json_obj)
        if policy.roles:
            logger.debug(
                "Service account has role(s) assigned: {}".format(str(policy.roles))
            )
            return True

    key_info = google_cloud_manager.get_service_account_keys_info(service_account)
    if key_info:
        logger.debug("Service account has key(s): {}".format(str(key_info)))
        return True
    return False


def is_service_account_from_google_project(
    service_account_email, project_id, project_number
):
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
        service_account_name = service_account_email.split("@")[0]

        if is_google_managed_service_account(service_account_email):
            return (
                service_account_name == "service-{}".format(project_number)
                or service_account_name == "project-{}".format(project_number)
                or service_account_name == project_number
                or service_account_name == project_id
            )

        # if it's a user-created project SA, the id is in the domain, otherwise,
        # attempt to parse it out of the name
        domain = service_account_email.split("@")[-1]
        if "iam.gserviceaccount.com" in domain:
            return domain.split(".")[0] == project_id

        return (
            service_account_name == "{}-compute".format(project_number)
            or service_account_name == project_id
        )

    except Exception as exc:
        logger.error(
            "Could not determine if service account (id: {} is from project"
            " (id: {}) due to error. Details: {}".format(
                service_account_email, project_id, exc
            )
        )
        return False


def is_user_member_of_google_project(
    user_id, google_cloud_manager, db=None, membership=None
):
    """
    Return whether or not the given user is a member of the provided
    Google project ID.

    This will verify that either the user's email or their linked Google
    account email exists as a member in the project.

    Args:
        user_id (int): User identifier
        google_cloud_manager (GoogleCloudManager): cloud manager instance
        db(str): db connection string
        membership (List(GooglePolicyMember) : pre-calculated list of members,
            Will make call to Google API if membership is None

    Returns:
        bool: whether or not the given user is a member of ALL of the provided
              Google project IDs
    """
    session = get_db_session(db)
    user = session.query(User).filter_by(id=user_id).first()
    if not user:
        logger.error(
            "Could not determine if user (id: {} is from project:"
            " {} due to error. User does not exist...".format(
                user_id, google_cloud_manager.project_id
            )
        )
        return False

    linked_google_account = (
        session.query(UserGoogleAccount)
        .filter(UserGoogleAccount.user_id == user_id)
        .first()
    )

    try:
        members = membership or google_cloud_manager.get_project_membership()
        member_emails = [member.email_id.lower() for member in members]
        # first check if user.email is in project, then linked account
        if not (user.email and user.email.lower() in member_emails):
            if not (
                linked_google_account
                and linked_google_account.email.lower() in member_emails
            ):
                # no user email is in project
                return False
    except Exception as exc:
        logger.error(
            "Could not determine if user (id: {}) is from project:"
            " {} due to error. Details: {}".format(
                user.id, getattr(google_cloud_manager, "project_id", "unknown"), exc
            )
        )
        return False

    return True


def is_user_member_of_all_google_projects(
    user_id, google_project_ids, db=None, membership=None
):
    """
    Return whether or not the given user is a member of ALL of the provided
    Google project IDs.

    This will verify that either the user's email or their linked Google
    account email exists as a member in the projects.

    Args:
        user_id (int): User identifier
        google_project_ids (List(str)): List of unique google project ids
        db(str): db connection string
        membership (List(GooglePolicyMember) : pre-calculated list of members,
            Will make call to Google API if membership is None

    Returns:
        bool: whether or not the given user is a member of ALL of the provided
              Google project IDs
    """
    is_member = False
    for google_project_id in google_project_ids:
        with GoogleCloudManager(google_project_id) as google_cloud_manager:
            is_member = is_user_member_of_google_project(
                user_id, google_cloud_manager, db, membership
            )

            if not is_member:
                return False

    return is_member


def get_user_by_linked_email(linked_email, db=None):
    """ "
    Return user identified by linked_email address

    Args:
        linked_email (str): email address linked to user

    Returns:
        (User): User db object
    """

    session = get_db_session(db)
    linked_account = (
        session.query(UserGoogleAccount)
        .filter(UserGoogleAccount.email == linked_email)
        .first()
    )
    if linked_account:
        user = session.query(User).filter(User.id == linked_account.user_id).first()
        return user
    else:
        return None


def get_user_by_email(user_email, db=None):
    """
    Return user from fence DB

    Args:
        user_id (str): user's fence email id

    Returns:
        bool: user in fence DB with user_email
    """

    session = get_db_session(db)
    user = (session.query(User).filter(User.email == user_email)).first()

    return user


def user_has_access_to_project(user, project_id, db=None):
    """
    Return True IFF user has access to provided project auth_id

    Args:
        user (fence.model.User): user to check access
        project_id (string): project auth_id
        db (str): database connection string

    Returns:
        bool: True IFF user has access to provided project auth_id

    """

    session = get_db_session(db)
    access_privilege = (
        session.query(AccessPrivilege)
        .filter(AccessPrivilege.user_id == user.id)
        .filter(AccessPrivilege.project_id == project_id)
    ).first()

    return bool(access_privilege)


def do_all_users_have_access_to_project(users, project_id, db=None):
    session = get_db_session(db)
    # users will be list of fence.model.User's
    # check if all users has access to a project with project_id
    for user in users:
        access_privilege = (
            session.query(AccessPrivilege)
            .filter(AccessPrivilege.user_id == user.id)
            .filter(AccessPrivilege.project_id == project_id)
        ).first()

        if not access_privilege:
            project = (session.query(Project).filter(Project.id == project_id)).first()
            project_rep = project.auth_id if project else project_id
            logger.info(
                "User ({}) does not have access to project ({}). There may be other "
                "users that do not have access to this project.".format(
                    user.username.lower(), project_rep
                )
            )
            return False

    return True


def patch_user_service_account(
    google_project_id, service_account_email, project_access, db=None
):
    """
    Update user service account which includes
    - Add and remove project access and bucket groups to/from fence db
    - Add and remove access members to/from google access group

    Args:
        google_project_id (str): google project id
        service_account_email (str): service account email
        project_access (List(str)): list of projects
        db(str): db connection string

    Returns:
        None
    """
    session = get_db_session(db)
    service_account = (
        session.query(UserServiceAccount).filter_by(email=service_account_email).first()
    )
    if not service_account:
        raise fence.errors.NotFound(
            "{} does not exist in DB".format(service_account_email)
        )

    accessed_project_ids = {
        ap.project_id
        for ap in (
            session.query(ServiceAccountAccessPrivilege)
            .filter_by(service_account_id=service_account.id)
            .all()
        )
    }

    granting_project_ids = get_project_ids_from_project_auth_ids(
        session, project_access
    )

    to_add = set.difference(granting_project_ids, accessed_project_ids)
    to_delete = set.difference(accessed_project_ids, granting_project_ids)

    _revoke_user_service_account_from_google(
        session, to_delete, google_project_id, service_account
    )

    # Use granting_project_ids here, not to_add, bc the google-delete-expired-service-account
    # job doesn't clean out the entries in the ServiceAccountAccessPrivilege table.
    # So the set diff (=to_add) won't include the proj if the SA was previously registered for that proj,
    # even if the SA later expired and was removed from the relevant GBAG.
    add_user_service_account_to_google(
        session, granting_project_ids, google_project_id, service_account
    )

    _revoke_user_service_account_from_db(session, to_delete, service_account)

    # On the other hand, use to_add here and not granting_project_ids,
    # otherwise this will add duplicates to ServiceAccountAccessPrivilege.
    # Because at time of writing, aforementioned tbl has no compound unique constraint.
    add_user_service_account_to_db(session, to_add, service_account)


def get_project_ids_from_project_auth_ids(session, auth_ids):
    """
    Return the Project.id's for the given list of Project.auth_id's

    Args:
        auth_ids (set(str)): list of project auth ids
    """
    project_ids = set()
    for project_auth_id in auth_ids:
        project = session.query(Project).filter_by(auth_id=project_auth_id).first()
        if not project:
            raise fence.errors.NotFound(
                "There is no {} in Fence db".format(project_auth_id)
            )
        project_ids.add(project.id)
    return project_ids


def _force_remove_service_account_from_access_db(
    service_account, access_groups, db=None
):
    """
    Remove the access of service account from db.

    Args:
        service_account (str): service account email
        db(str): db connection string

    Returns:
        None

    Restrictions:
        service account has to exist in db

    """
    session = get_db_session(db)

    for bucket_access_group in access_groups:
        sa_to_group = (
            session.query(ServiceAccountToGoogleBucketAccessGroup)
            .filter_by(
                service_account_id=service_account.id,
                access_group_id=bucket_access_group.id,
            )
            .first()
        )
        if sa_to_group:
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
    service_account_email, google_project_id, db=None
):
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
        session.query(UserServiceAccount).filter_by(email=service_account_email).first()
    )

    if not service_account:
        raise fence.errors.NotFound(
            "{} does not exist in DB".format(service_account_email)
        )

    access_groups = get_google_access_groups_for_service_account(service_account)

    for bucket_access_group in access_groups:
        try:
            with GoogleCloudManager(google_project_id, use_default=False) as g_manager:
                g_manager.remove_member_from_group(
                    member_email=service_account.email,
                    group_id=bucket_access_group.email,
                )
        except Exception as exc:
            raise GoogleAPIError(
                "Can not remove member {} from access group {}. Detail {}".format(
                    service_account.email, bucket_access_group.email, exc
                )
            )

    _force_remove_service_account_from_access_db(service_account, access_groups, db)


def force_remove_service_account_from_db(service_account_email, db=None):
    """
    remove service account from user_service_account table

    Args:
        service_account_email(str): service account to be removed from db
        db(None, str): Optional db connection string
    """
    session = get_db_session(db)
    service_account = (
        session.query(UserServiceAccount).filter_by(email=service_account_email).first()
    )

    if not service_account:
        logger.info(
            "Service account ({}) requested for removal from database "
            "was not found in the database.".format(service_account_email)
        )
    else:
        session.delete(service_account)
        session.commit()

    return


def _revoke_user_service_account_from_google(
    session, to_delete_project_ids, google_project_id, service_account
):
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
                with GoogleCloudManager(
                    google_project_id, use_default=False
                ) as g_manager:
                    if not g_manager.remove_member_from_group(
                        member_email=service_account.email, group_id=access_group.email
                    ):

                        logger.debug(
                            "Removed {} from google group {}".format(
                                service_account.email, access_group.email
                            )
                        )
                    else:
                        raise GoogleAPIError("Can not remove {} from group {}")
            except Exception as exc:
                raise GoogleAPIError(
                    "Can not remove {} from group {}. Detail {}".format(
                        service_account.email, access_group.email, exc
                    )
                )


def add_user_service_account_to_google(
    session, to_add_project_ids, google_project_id, service_account
):
    """
    Add service account to Google access groups

    Args:
        session(current_session): db session
        to_add_project_ids (List(id)): list of project ids
        google_project_id (str): google project id
        service_account (UserServiceAccount): user service account

    """
    logger.debug(
        "attempting to add {} to groups for projects: {}".format(
            service_account, to_add_project_ids
        )
    )
    for project_id in to_add_project_ids:
        access_groups = _get_google_access_groups(session, project_id)
        logger.debug(
            "google group(s) for project {}: {}".format(project_id, access_groups)
        )
        for access_group in access_groups:
            try:
                # TODO: Need to remove try/catch after major refactor
                with GoogleCloudManager(
                    google_project_id, use_default=False
                ) as g_manager:
                    response = g_manager.add_member_to_group(
                        member_email=service_account.email, group_id=access_group.email
                    )
                    if response.get("email", None):
                        logger.debug(
                            "Successfully add member {} to Google group {}.".format(
                                service_account.email, access_group.email
                            )
                        )
                    else:
                        raise GoogleAPIError(
                            "Can not add {} to Google group {}".format(
                                service_account.email, access_group.email
                            )
                        )

            except Exception as exc:
                raise GoogleAPIError(
                    "Can not add {} to Google group {}. Detail {}".format(
                        service_account.email, access_group.email, exc
                    )
                )


def _revoke_user_service_account_from_db(
    session, to_delete_project_ids, service_account
):
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
            session.query(ServiceAccountAccessPrivilege)
            .filter_by(project_id=project_id, service_account_id=service_account.id)
            .first()
        )
        session.delete(access_project)

        access_groups = _get_google_access_groups(session, project_id)
        for access_group in access_groups:
            account_access_bucket_group = (
                session.query(ServiceAccountToGoogleBucketAccessGroup)
                .filter_by(
                    service_account_id=service_account.id,
                    access_group_id=access_group.id,
                )
                .first()
            )
            if account_access_bucket_group:
                session.delete(account_access_bucket_group)

    session.commit()


def add_user_service_account_to_db(session, to_add_project_ids, service_account):
    """
    Add user service account to service account
    access privilege and service account bucket access group

    Args:
        sess(current_session): db session
        to_add_project_ids(List(int)): List of project id
        service_account(UserServiceAccount): user service account
        requested_expires_in(int): requested time (in seconds) during which
            the SA has bucket access

    Returns:
        None

    Contrains:
        The service account is not in DB yet

    """
    for project_id in to_add_project_ids:
        session.add(
            ServiceAccountAccessPrivilege(
                project_id=project_id, service_account_id=service_account.id
            )
        )

        access_groups = _get_google_access_groups(session, project_id)

        # timestamp at which the SA will lose bucket access
        # by default: use configured time or 7 days
        expiration_time = int(time.time()) + config.get(
            "GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN", 604800
        )
        requested_expires_in = (
            get_valid_expiration_from_request()
        )  # requested time (in seconds)
        if requested_expires_in:
            # convert it to timestamp
            requested_expiration = int(time.time()) + requested_expires_in
            expiration_time = min(expiration_time, requested_expiration)

        for access_group in access_groups:
            sa_to_group = ServiceAccountToGoogleBucketAccessGroup(
                service_account_id=service_account.id,
                expires=expiration_time,
                access_group_id=access_group.id,
            )
            session.add(sa_to_group)

    session.commit()


def get_registered_service_account_from_email(service_account_email):
    """
    Parse email to get google project id
    """
    session = get_db_session()
    return (
        session.query(UserServiceAccount).filter_by(email=service_account_email).first()
    )


def get_google_project_from_user_managed_service_account_email(service_account_email):
    """
    Parse email to get google project id for a User-Managed service account
    """
    words = service_account_email.split("@")
    return words[1].split(".")[0]


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
        set(GoogleBucketAccessGroup)
    """
    access_groups = set()
    project = session.query(Project).filter_by(id=project_id).first()

    for bucket in project.buckets:
        groups = bucket.google_bucket_access_groups
        access_groups.update(groups)

    return access_groups


def extend_service_account_access(service_account_email, db=None):
    """
    Extend the Google service accounts access to data by extending the
    expiration time for each of the Google Bucket Access Groups it's in.

    WARNING: This does NOT do any AuthZ, do before this.

    Args:
        service_account_email (str): service account email
        db(str): db connection string
    """
    session = get_db_session(db)

    service_account = (
        session.query(UserServiceAccount).filter_by(email=service_account_email).first()
    )

    if service_account:
        bucket_access_groups = get_google_access_groups_for_service_account(
            service_account
        )

        # timestamp at which the SA will lose bucket access
        # by default: use configured time or 7 days
        expiration_time = int(time.time()) + config.get(
            "GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN", 604800
        )
        requested_expires_in = get_valid_expiration_from_request()
        if requested_expires_in:
            requested_expiration = int(time.time()) + requested_expires_in
            expiration_time = min(expiration_time, requested_expiration)

        logger.debug(
            "Service Account ({}) access extended to {}.".format(
                service_account.email, expiration_time
            )
        )
        for access_group in bucket_access_groups:
            bucket_access = (
                session.query(ServiceAccountToGoogleBucketAccessGroup)
                .filter_by(
                    service_account_id=service_account.id,
                    access_group_id=access_group.id,
                )
                .first()
            )
            if not bucket_access:
                bucket_access = ServiceAccountToGoogleBucketAccessGroup(
                    service_account_id=service_account.id,
                    access_group_id=access_group.id,
                    expires=expiration_time,
                )
                session.add(bucket_access)

            bucket_access.expires = expiration_time

        session.commit()


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

    project = session.query(Project).filter_by(auth_id=project_auth_id).first()

    return project


def remove_white_listed_service_account_ids(sa_ids):
    """
    Remove any service account emails that should be ignored when
    determining validitity.

    Args:
        sa_ids (List[str]): Service account emails

    Returns:
        List[str]: Service account emails
    """
    white_listed_sa_emails = config.get("WHITE_LISTED_SERVICE_ACCOUNT_EMAILS", [])

    logger.debug(
        "Removing whitelisted SAs {} from the SAs on the project.".format(
            white_listed_sa_emails
        )
    )

    monitoring_service_account = get_monitoring_service_account_email()

    if monitoring_service_account in sa_ids:
        sa_ids.remove(monitoring_service_account)

    for email in white_listed_sa_emails:
        if email in sa_ids:
            sa_ids.remove(email)

    return sa_ids


def is_org_whitelisted(parent_org):
    """
    Return whether or not the provide Google parent organization is whitelisted

    Args:
        parent_org (str): Google parent organization

    Returns:
        bool: whether or not the provide Google parent organization is whitelisted
    """

    white_listed_google_parent_orgs = config.get("WHITE_LISTED_GOOGLE_PARENT_ORGS", {})

    # make sure we're comparing same types
    return str(parent_org) in [
        str(parent_org) for parent_org in white_listed_google_parent_orgs
    ]


def force_delete_service_account(service_account_email, db=None):
    """
    Delete from our db the given user service account by email.
     Args:
        service_account_email (str): user service account email
        db(str): db connection string
    """
    session = get_db_session(db)
    sa = (
        session.query(UserServiceAccount).filter_by(email=service_account_email).first()
    )
    if sa:
        session.delete(sa)
        session.commit()


def force_add_service_accounts_to_access(
    service_account_emails, google_project_id, project_access, db=None
):
    """
    service_account_emails(list(str)): list of account emails
    google_project_id(str):  google project id
    project_access(list(str)): list of projects
    db(str): db connection string
    """
    session = get_db_session(db)

    with GoogleCloudManager(google_project_id) as google_project:
        for service_account_email in service_account_emails:
            g_service_account = google_project.get_service_account(
                service_account_email
            )
            sa = (
                session.query(UserServiceAccount)
                .filter_by(email=service_account_email)
                .first()
            )
            if not sa:
                sa = UserServiceAccount(
                    google_unique_id=g_service_account.get("uniqueId"),
                    email=service_account_email,
                    google_project_id=google_project_id,
                )
                session.add(sa)
                session.commit()

            project_ids = set()
            for project in project_access:
                project_db = session.query(Project).filter_by(auth_id=project).first()
                if project_db:
                    project_ids.add(project_db.id)

            add_user_service_account_to_db(session, project_ids, sa)

            add_user_service_account_to_google(
                session, project_ids, google_project_id, sa
            )


def get_service_account_policy(account, google_cloud_manager):
    """
    Get the policy for the service account identified by `account`,
    using the provided cloud_manager

    Args:
        account(str): service account identifier
        google_cloud_manager: cloud_manager instance
    Returns:
        (Response): returns response from Google API

    """
    sa_policy = google_cloud_manager.get_service_account_policy(account)
    if sa_policy.status_code != 200:
        raise NotFound(
            "Unable to get Service Account policy (status: {})".format(
                sa_policy.status_code
            )
        )
    else:
        return sa_policy
