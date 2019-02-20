"""
Google Monitoring and Validation Logic

This file contains scripts to monitor user-registered service accounts and
their respective Google projects. The functions in this file will also
handle invalid service accounts and projects.
"""
import traceback

from cirrus.google_cloud.iam import GooglePolicyMember
from cirrus import GoogleCloudManager
from cdislogging import get_logger

from fence.resources.google.validity import (
    GoogleProjectValidity,
    GoogleServiceAccountValidity,
)

from fence.resources.google.utils import (
    get_all_registered_service_accounts,
    get_linked_google_account_email,
    is_google_managed_service_account,
)

from fence.resources.google.access_utils import (
    get_google_project_number,
    get_project_from_auth_id,
    get_user_by_email,
    get_user_by_linked_email,
    force_remove_service_account_from_access,
    force_remove_service_account_from_db,
    user_has_access_to_project,
)

from fence import utils
from fence.config import config
from fence.models import User
from fence.errors import Unauthorized

logger = get_logger(__name__)


def validation_check(db):
    """
    Google validation check for all user-registered service accounts
    and projects.

    This will remove any invalid registered service accounts. It will also
    remove all registered service accounts for a given project if the project
    itself is invalid.

    NOTE: This entire function should be time-efficient and finish in less
          than 90 seconds.
          TODO: Test this function with various amounts of service accounts
                and delays from the google API
    """
    registered_service_accounts = get_all_registered_service_accounts(db=db)
    project_service_account_mapping = _get_project_service_account_mapping(
        registered_service_accounts
    )

    for google_project_id, sa_emails in project_service_account_mapping.iteritems():
        email_required = False
        invalid_registered_service_account_reasons = {}
        invalid_project_reasons = {}
        sa_emails_removed = []
        for sa_email in sa_emails:
            logger.debug("Validating Google Service Account: {}".format(sa_email))
            # Do some basic service account checks, this won't validate
            # the data access, that's done when the project's validated
            try:
                validity_info = _is_valid_service_account(sa_email, google_project_id)
            except Unauthorized:
                """
                is_validity_service_account can raise an exception if the monitor does
                not have access, which will be caught and handled during the Project check below
                The logic in the endpoints is reversed (Project is checked first,
                not SAs) which is why there's is a sort of weird handling of it here.
                """
                logger.info(
                    "Monitor does not have access to validate "
                    "service account {}. This should be handled "
                    "in project validation."
                )
                continue

            if not validity_info:
                logger.info(
                    "INVALID SERVICE ACCOUNT {} DETECTED. REMOVING. Validity Information: {}".format(
                        sa_email, str(getattr(validity_info, "_info", None))
                    )
                )
                force_remove_service_account_from_access(
                    sa_email, google_project_id, db=db
                )
                if validity_info["policy_accessible"] is False:
                    logger.info(
                        "SERVICE ACCOUNT POLICY NOT ACCESSIBLE OR DOES NOT "
                        "EXIST. SERVICE ACCOUNT WILL BE REMOVED FROM FENCE DB"
                    )
                    force_remove_service_account_from_db(sa_email, db=db)

                # remove from list so we don't try to remove again
                # if project is invalid too
                sa_emails_removed.append(sa_email)

                invalid_registered_service_account_reasons[
                    sa_email
                ] = _get_service_account_removal_reasons(validity_info)
                email_required = True

        for sa_email in sa_emails_removed:
            sa_emails.remove(sa_email)

        logger.debug("Validating Google Project: {}".format(google_project_id))
        google_project_validity = _is_valid_google_project(google_project_id, db=db)

        if not google_project_validity:
            # for now, if we detect in invalid project, remove ALL service
            # accounts from access for that project.
            #
            # TODO: If the issue is ONLY a specific service account,
            # it may be possible to isolate it and only remove that
            # from access.
            logger.info(
                "INVALID GOOGLE PROJECT {} DETECTED. REMOVING ALL SERVICE ACCOUNTS. "
                "Validity Information: {}".format(
                    google_project_id,
                    str(getattr(google_project_validity, "_info", None)),
                )
            )
            for sa_email in sa_emails:
                force_remove_service_account_from_access(
                    sa_email, google_project_id, db=db
                )

            # projects can be invalid for project-related reasons or because
            # of NON-registered service accounts
            invalid_project_reasons["general"] = _get_general_project_removal_reasons(
                google_project_validity
            )
            invalid_project_reasons[
                "non_registered_service_accounts"
            ] = _get_invalid_sa_project_removal_reasons(google_project_validity)
            invalid_project_reasons["access"] = _get_access_removal_reasons(
                google_project_validity
            )
            email_required = True

        if email_required:
            logger.debug(
                "Sending email with service account removal reasons: {} and project "
                "removal reasons: {}.".format(
                    invalid_registered_service_account_reasons, invalid_project_reasons
                )
            )
            _send_emails_informing_service_account_removal(
                _get_user_email_list_from_google_project_with_owner_role(
                    google_project_id
                ),
                invalid_registered_service_account_reasons,
                invalid_project_reasons,
                google_project_id,
            )


def _is_valid_service_account(sa_email, google_project_id):
    """
    Validate the given registered service account and remove if invalid.

    Args:
        sa_email(str): service account email
        google_project_id(str): google project id
    """
    with GoogleCloudManager(google_project_id) as gcm:
        google_project_number = get_google_project_number(google_project_id, gcm)

    has_access = bool(google_project_number)
    if not has_access:
        # if our monitor doesn't have access at this point, just don't return any
        # information. When the project check runs, it will catch the monitor missing
        # error and add it to the removal reasons
        raise Unauthorized

    try:
        sa_validity = GoogleServiceAccountValidity(
            sa_email, google_project_id, google_project_number=google_project_number
        )

        if is_google_managed_service_account(sa_email):
            sa_validity.check_validity(
                early_return=True,
                check_type=True,
                check_policy_accessible=True,
                check_external_access=False,
            )
        else:
            sa_validity.check_validity(
                early_return=True,
                check_type=True,
                check_policy_accessible=True,
                check_external_access=True,
            )

    except Exception as exc:
        # any issues, assume invalid
        # TODO not sure if this is the right way to handle this...
        logger.warning(
            "Service Account {} determined invalid due to unhandled exception: {}. "
            "Assuming service account is invalid.".format(sa_email, str(exc))
        )
        traceback.print_exc()
        sa_validity = None

    return sa_validity


def _is_valid_google_project(google_project_id, db=None):
    """
    Validate the given google project id and remove all registered service
    accounts under that project if invalid.
    """
    try:
        project_validity = GoogleProjectValidity(google_project_id)
        project_validity.check_validity(early_return=True, db=db)
    except Exception as exc:
        # any issues, assume invalid
        # TODO not sure if this is the right way to handle this...
        logger.warning(
            "Project {} determined invalid due to unhandled exception: {}. "
            "Assuming project is invalid.".format(google_project_id, str(exc))
        )
        traceback.print_exc()
        project_validity = None

    return project_validity


def _get_service_account_removal_reasons(service_account_validity):
    """
    Get service account removal reason

    Args:
        service_account_validity(GoogleServiceAccountValidity): service account validity

    Returns:
        List[str]: the reason(s) the service account was removed
    """
    removal_reasons = []

    if service_account_validity is None:
        return removal_reasons

    if service_account_validity["valid_type"] is False:
        removal_reasons.append(
            "It must be a Compute Engine service account or an user-managed service account."
        )
    if service_account_validity["no_external_access"] is False:
        removal_reasons.append(
            "It has either roles attached to it or service account keys generated. We do not allow this because we need to restrict external access."
        )
    if service_account_validity["owned_by_project"] is False:
        removal_reasons.append("It is not owned by the project.")
    if service_account_validity["policy_accessible"] is False:
        removal_reasons.append(
            "Either it doesn't exist in Google or "
            "we could not access its policy, "
            "which is need for further checks."
        )

    return removal_reasons


def _get_general_project_removal_reasons(google_project_validity):
    """
    Get service account removal reason

    Args:
        google_project_validity(GoogleProjectValidity): google project validity

    Returns:
        List[str]: the reason(s) project was removed
    """
    removal_reasons = []

    if google_project_validity is None:
        return removal_reasons

    if google_project_validity["user_has_access"] is False:
        removal_reasons.append("User isn't a member on the Google Project.")

    if google_project_validity["monitor_has_access"] is False:
        removal_reasons.append(
            "Cannot access the project, ensure monitoring service accounts have necessary permissions."
        )

    if google_project_validity["valid_parent_org"] is False:
        removal_reasons.append("Google Project has a parent orgnization.")

    if google_project_validity["valid_member_types"] is False:
        removal_reasons.append(
            "There are members in the Google Project other than Google Users or Google Service Accounts."
        )

    if google_project_validity["members_exist_in_fence"] is False:
        removal_reasons.append(
            "Some Google Users on the Google Project do not exist in authentication database."
        )

    return removal_reasons


def _get_invalid_sa_project_removal_reasons(google_project_validity):
    """
    Get invalid non-registered service account removal reasons

    Args:
        google_project_validity(GoogleProjectValidity): google project validity

    Returns:
        dict: service_account_email: ["list of of why removed", "more reasons"]
    """
    removal_reasons = {}

    if google_project_validity is None:
        return removal_reasons

    for sa_email, sa_validity in google_project_validity.get("service_accounts", {}):
        if not sa_validity:
            removal_reasons[sa_email] = _get_service_account_removal_reasons(
                sa_validity
            )

    return removal_reasons


def _get_access_removal_reasons(google_project_validity):

    removal_reasons = {}

    if google_project_validity is None:
        return removal_reasons

    for project, access_validity in google_project_validity.get("access", {}):
        removal_reasons[project] = []
        if access_validity["exists"] is False:
            removal_reasons[project].append(
                "Data access project {} no longer exists.".format(project)
            )

        if access_validity["all_users_have_access"] is False:
            removal_reasons[project].append(
                "Not all users on the Google Project have access to data project {}.".format(
                    project
                )
            )

    return removal_reasons


def _get_google_project_ids_from_service_accounts(registered_service_accounts):
    """
    Return a set of just the google project ids that have registered
    service accounts.
    """
    google_projects = set([sa.google_project_id for sa in registered_service_accounts])
    return google_projects


def _get_project_service_account_mapping(registered_service_accounts):
    """
    Return a dict with google projects as keys and a list of service accounts
    as values.

    Example:
    {
        'project_a': [
            'service_acount_a@email.com',
            'service_acount_b@email.com'
        ],
        'project_b': [
            'service_acount_c@email.com',
            'service_acount_d@email.com'
        ]
    }
    """
    output = {}
    for sa in registered_service_accounts:
        if sa.google_project_id in output:
            output[sa.google_project_id].append(sa.email)
        else:
            output[sa.google_project_id] = [sa.email]

    return output


def _get_user_email_list_from_google_project_with_owner_role(project_id):
    """
    Get a list of emails associated to google project id

    Args:
        project_id(str): project id

    Returns:
        list(str): list of emails belong to the project

    """

    with GoogleCloudManager(project_id, use_default=False) as prj:
        members = prj.get_project_membership(project_id)
        users = [
            member
            for member in members
            if member.member_type == GooglePolicyMember.USER
        ]

        return list(
            {
                u.email_id
                for u in users
                for role in u.roles
                if role.name.upper() == "OWNER"
            }
        )


def _send_emails_informing_service_account_removal(
    to_emails, invalid_service_account_reasons, invalid_project_reasons, project_id
):
    """
    Send emails to list of emails

    Args:
        to_emails(list(str)): list of email addaresses
        invalid_service_account_reasons(dict): removal reasons of service accounts
        project_id(str): google project id

    Returns:
        httpResponse or None: None if input list is empty

    Exceptions:
        ValueError

    """

    if not to_emails:
        return None

    from_email = config["REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION"]["from"]
    subject = config["REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION"]["subject"]

    domain = config["REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION"]["domain"]
    if config["REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION"]["admin"]:
        to_emails.extend(config["REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION"]["admin"])

    text = config["REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION"]["content"]
    content = text.format(project_id)

    for email, removal_reasons in invalid_service_account_reasons.iteritems():
        if removal_reasons:
            content += "\n\t - Service account {} was removed from Google Project {}.".format(
                email, project_id
            )
            for reason in removal_reasons:
                content += "\n\t\t - {}".format(reason)

    general_project_errors = invalid_project_reasons.get("general", {})
    non_reg_sa_errors = invalid_project_reasons.get(
        "non_registered_service_accounts", {}
    )
    access_errors = invalid_project_reasons.get("access")
    if general_project_errors or non_reg_sa_errors or access_errors:
        content += (
            "\n\t - Google Project {} determined invalid. All service "
            "accounts with data access will be removed from access.".format(project_id)
        )
        for removal_reason in general_project_errors:
            if removal_reason:
                content += "\n\t\t - {}".format(removal_reason)

        if access_errors:
            for project, removal_reasons in access_errors.iteritems():
                for reason in removal_reasons:
                    content += "\n\t\t - {}".format(reason)

        if non_reg_sa_errors:
            for sa_email, removal_reasons in non_reg_sa_errors.iteritems():
                content += "\n\t\t - Google Project Service Account {} determined invalid.".format(
                    sa_email
                )
                for reason in removal_reasons:
                    content += "\n\t\t\t - {}".format(reason)

    return utils.send_email(from_email, to_emails, subject, content, domain)


def _get_users_without_access(db, auth_ids, user_emails, check_linking):
    """
    Build list of users without access to projects identified by auth_ids

    Args:
        db (str): database instance
        auth_ids (list(str)): list of project auth_ids to check access against
        user_emails (list(str)): list of emails to check access for
        check_linking (bool): flag to check for linked google email

    Returns:
        dict{str : (list(str))} : dictionary where keys are user emails,
        and values are list of project_ids they do not have access to

    """

    no_access = {}

    for user_email in user_emails:

        user = get_user_by_email(user_email, db) or get_user_by_linked_email(
            user_email, db
        )

        logger.info("Checking access for {}.".format(user.email))

        if not user:
            logger.info(
                "Email ({}) does not exist in fence database.".format(user_email)
            )
            continue

        if check_linking:
            link_email = get_linked_google_account_email(user.id, db)
            if not link_email:
                logger.info(
                    "User ({}) does not have a linked google account.".format(
                        user_email
                    )
                )
                continue

        no_access_auth_ids = []
        for auth_id in auth_ids:
            project = get_project_from_auth_id(auth_id, db)
            if project:
                if not user_has_access_to_project(user, project.id, db):
                    logger.info(
                        "User ({}) does NOT have access to project (auth_id: {})".format(
                            user_email, auth_id
                        )
                    )
                    # add to list to send email
                    no_access_auth_ids.append(auth_id)
                else:
                    logger.info(
                        "User ({}) has access to project (auth_id: {})".format(
                            user_email, auth_id
                        )
                    )
            else:
                logger.warning("Project (auth_id: {}) does not exist.".format(auth_id))

        if no_access_auth_ids:
            no_access[user_email] = no_access_auth_ids

    return no_access


def email_user_without_access(user_email, projects, google_project_id):

    """
    Send email to user, indicating no access to given projects

    Args:
        user_email (str): address to send email to
        projects (list(str)):  list of projects user does not have access to that they should
        google_project_id (str): id of google project user belongs to
    Returns:
        HTTP response

    """
    to_emails = [user_email]

    from_email = config["PROBLEM_USER_EMAIL_NOTIFICATION"]["from"]
    subject = config["PROBLEM_USER_EMAIL_NOTIFICATION"]["subject"]

    domain = config["PROBLEM_USER_EMAIL_NOTIFICATION"]["domain"]
    if config["PROBLEM_USER_EMAIL_NOTIFICATION"]["admin"]:
        to_emails.extend(config["PROBLEM_USER_EMAIL_NOTIFICATION"]["admin"])

    text = config["PROBLEM_USER_EMAIL_NOTIFICATION"]["content"]
    content = text.format(google_project_id, ",".join(projects))

    return utils.send_email(from_email, to_emails, subject, content, domain)


def email_users_without_access(
    db, auth_ids, user_emails, check_linking, google_project_id
):

    """
    Build list of users without acess and send emails.

    Args:
        db (str): database instance
        auth_ids (list(str)): list of project auth_ids to check access against
        user_emails (list(str)): list of emails to check access for
        check_linking (bool): flag to check for linked google email
    Returns:
        None
    """
    users_without_access = _get_users_without_access(
        db, auth_ids, user_emails, check_linking
    )

    if len(users_without_access) == len(user_emails):
        logger.warning(
            "No user has proper access to provided projects. Contact project administrator. No emails will be sent"
        )
        return
    elif len(users_without_access) > 0:
        logger.info(
            "Some user(s) do not have proper access to provided projects. Email(s) will be sent to user(s)."
        )

        with GoogleCloudManager(google_project_id) as gcm:
            members = gcm.get_project_membership(google_project_id)
            users = []
            for member in members:
                if member.member_type == GooglePolicyMember.USER:
                    users.append(member.email_id)

        for user, projects in users_without_access.iteritems():
            logger.info(
                "{} does not have access to the following datasets: {}.".format(
                    user, ",".join(projects)
                )
            )
            if user in users:
                logger.info(
                    "{} is a member of google project: {}. User will be emailed.".format(
                        user, google_project_id
                    )
                )
                email_user_without_access(user, projects, google_project_id)
            else:
                logger.info(
                    "{} is NOT a member of google project: {}. User will NOT be emailed.".format(
                        user, google_project_id
                    )
                )
    else:
        logger.info("All users have proper access to provided projects.")
