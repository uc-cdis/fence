"""
Google Monitoring and Validation Logic

This file contains scripts to monitor user-registered service accounts and
their respective Google projects. The functions in this file will also
handle invalid service accounts and projects.
"""
from cirrus.google_cloud.iam import GooglePolicyMember
from cirrus import GoogleCloudManager

from fence.resources.google.validity import (
    GoogleProjectValidity,
    GoogleServiceAccountValidity,
)

from fence.resources.google.utils import get_all_registered_service_accounts
from fence.resources.google.access_utils import (
    force_remove_service_account_from_access,
)

from fence import utils


def validation_check(db, config=None):
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
        invalid_service_account_reasons = {}
        for sa_email in sa_emails:
            print("Validating Google Service Account: {}".format(sa_email))
            # Do some basic service account checks, this won't validate
            # the data access, that's done when the project's validated
            validity_info = _is_valid_service_account(sa_email, google_project_id, config=config)
            if not validity_info:
                print(
                    "INVALID SERVICE ACCOUNT {} DETECTED. REMOVING...".format(sa_email)
                )
                force_remove_service_account_from_access(
                    sa_email, google_project_id, db=db
                )
                invalid_service_account_reasons[sa_email] = (
                    _get_service_account_removal_reason(validity_info))

        print("Validating Google Project: {}".format(google_project_id))
        google_project_validity = _is_valid_google_project(google_project_id, db=db, config=config)
        if not google_project_validity:
            # for now, if we detect in invalid project, remove ALL service
            # accounts from access for that project.
            #
            # TODO: If the issue is ONLY a specific service account,
            # it may be possible to isolate it and only remove that
            # from access.
            print(
                "INVALID GOOGLE PROJECT {} DETECTED. "
                "REMOVING ALL SERVICE ACCOUNTS...".format(google_project_id)
            )
            for sa_email in sa_emails:
                force_remove_service_account_from_access(
                    sa_email, google_project_id, db=db
                )
            invalid_service_account_reasons[sa_email] = (
                _get_project_removal_reason(google_project_validity))

        _send_emails_informing_service_account_removal(
            _get_user_email_list_from_google_project_with_owner_role(
                google_project_id),
            invalid_service_account_reasons, google_project_id)


def _is_valid_service_account(sa_email, google_project_id, config=None):
    """
    Validate the given registered service account and remove if invalid.

    Args:
        sa_email(str): service account email
        google_project_id(str): google project id
    """
    try:
        sa_validity = GoogleServiceAccountValidity(sa_email, google_project_id)
        sa_validity.check_validity(
                early_return=True, config=config)
    except Exception:
        # any issues, assume invalid
        # TODO not sure if this is the right way to handle this...
        sa_validity = None

    return sa_validity


def _is_valid_google_project(google_project_id, db=None, config=None):
    """
    Validate the given google project id and remove all registered service
    accounts under that project if invalid.
    """
    try:
        project_validity = GoogleProjectValidity(google_project_id)
        project_validity.check_validity(
                early_return=True, db=db, config=config)
    except Exception:
        # any issues, assume invalid
        # TODO not sure if this is the right way to handle this...
        project_validity = None

    return project_validity


def _get_service_account_removal_reason(service_account_validity):
    """
    Get service account removal reason

    Args:
        service_account_validity(GoogleServiceAccountValidity): service account validity

    Returns:
        str: the reason service account was removed
    """
    if service_account_validity is None:
        return ""

    removal_reason = ""

    if service_account_validity['valid_type'] is False:
        removal_reason += "\n\t\t-It must be a Compute Engine service account or an user-managed service account."
    if service_account_validity['no_external_access'] is False:
        removal_reason += "\n\t\t-It has either roles attached to it or service account keys generated. We do not allow this because we need to restrict external access.\n"
    if service_account_validity['owned_by_project'] is False:
        removal_reason += "\n\t\t-It is not owned by the project.\n"

    return removal_reason


def _get_project_removal_reason(google_project_validity):
    """
    Get service account removal reason

    Args:
        google_project_validity(GoogleProjectValidity): google project validity

    Returns:
        str: the reason project was removed
    """

    if google_project_validity is None:
        return ""

    removal_reason = ""

    if google_project_validity["user_has_access"] is False:
        removal_reason += "\n\t\t-User isn't a member on the project."

    if google_project_validity["monitor_has_access"] is False:
        removal_reason += "\n\t\t-Can not access the project."

    if google_project_validity["valid_parent_org"] is False:
        removal_reason += "\n\t\t-Project has a parent orgnization."

    if google_project_validity["valid_member_types"] is False:
        removal_reason += "\n\t\t-There are members in the project other than Google users or Google service accounts."

    if google_project_validity["members_exist_in_fence"] is False:
        removal_reason += "\n\t\t-Some Google members do not exist in authentication database."

    return removal_reason


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

        return list({
            u.email_id
            for u in users
            for role in u.roles
            if role.name.upper() == "OWNER"})


def _send_emails_informing_service_account_removal(
            to_emails, invalid_service_account_reasons, project_id):
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

    from fence.settings import REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION
    from_email = REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["from"]
    subject = REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["subject"]

    domain = REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["domain"]
    if REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["admin"]:
        to_emails.extend(REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["admin"])

    text = REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["content"]
    content = text.format(project_id)

    for email, removal_reason in invalid_service_account_reasons.iteritems():
        if removal_reason:
            content += ("\n\t - Service account {} was removed from Google project {} {}"
                        .format(email, project_id, removal_reason))

    return utils.send_email(from_email, to_emails, subject, content, domain)
