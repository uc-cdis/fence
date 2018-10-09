"""
Google Monitoring and Validation Logic

This file contains scripts to monitor user-registered service accounts and
their respective Google projects. The functions in this file will also
handle invalid service accounts and projects.
"""
import traceback
from cirrus.google_cloud.iam import GooglePolicyMember
from cirrus import GoogleCloudManager

from fence.resources.google.validity import (
    GoogleProjectValidity,
    GoogleServiceAccountValidity,
)

from fence.resources.google.utils import get_all_registered_service_accounts
from fence.resources.google.access_utils import (
    get_google_project_number,
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
    email_required = False
    registered_service_accounts = get_all_registered_service_accounts(db=db)
    project_service_account_mapping = _get_project_service_account_mapping(
        registered_service_accounts
    )
    invalid_registered_service_account_reasons = {}
    invalid_project_reasons = {}

    for google_project_id, sa_emails in project_service_account_mapping.iteritems():
        for sa_email in sa_emails:
            print("Validating Google Service Account: {}".format(sa_email))
            # Do some basic service account checks, this won't validate
            # the data access, that's done when the project's validated
            validity_info = _is_valid_service_account(
                sa_email, google_project_id, config=config
            )
            if not validity_info:
                print(
                    "INVALID SERVICE ACCOUNT {} DETECTED. REMOVING...".format(sa_email)
                )
                force_remove_service_account_from_access(
                    sa_email, google_project_id, db=db
                )
                # remove from list so we don't try to remove again
                # if project is invalid too
                sa_emails.remove(sa_email)

                invalid_registered_service_account_reasons[
                    sa_email
                ] = _get_service_account_removal_reasons(validity_info)
                email_required = True

        print("Validating Google Project: {}".format(google_project_id))
        google_project_validity = _is_valid_google_project(
            google_project_id, db=db, config=config
        )
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

            # projects can be invalid for project-related reasons or because
            # of NON-registered service accounts
            invalid_project_reasons["general"] = _get_general_project_removal_reasons(
                google_project_validity
            )
            invalid_project_reasons[
                "non_registered_service_accounts"
            ] = _get_invalid_sa_project_removal_reasons(google_project_validity)
            email_required = True

        if email_required:
            _send_emails_informing_service_account_removal(
                _get_user_email_list_from_google_project_with_owner_role(
                    google_project_id
                ),
                invalid_registered_service_account_reasons,
                invalid_project_reasons,
                google_project_id,
            )


def _is_valid_service_account(sa_email, google_project_id, config=None):
    """
    Validate the given registered service account and remove if invalid.

    Args:
        sa_email(str): service account email
        google_project_id(str): google project id
    """
    google_project_number = get_google_project_number(google_project_id)
    has_access = bool(google_project_number)
    if not has_access:
        # if our monitor doesn't have access at this point, just don't return any
        # information. When the project check runs, it will catch the monitor missing
        # error and add it to the removal reasons
        return None

    try:
        sa_validity = GoogleServiceAccountValidity(
            sa_email, google_project_id, google_project_number=google_project_number
        )
        sa_validity.check_validity(early_return=True, config=config)
    except Exception:
        # any issues, assume invalid
        # TODO not sure if this is the right way to handle this...
        print("Service Account determined invalid due to unhandled exception:")
        traceback.print_exc()
        sa_validity = None

    return sa_validity


def _is_valid_google_project(google_project_id, db=None, config=None):
    """
    Validate the given google project id and remove all registered service
    accounts under that project if invalid.
    """
    try:
        project_validity = GoogleProjectValidity(google_project_id)
        project_validity.check_validity(early_return=True, db=db, config=config)

    except Exception:
        # any issues, assume invalid
        # TODO not sure if this is the right way to handle this...
        print("Project determined invalid due to unhandled exception:")
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

    from fence.settings import REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION

    from_email = REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["from"]
    subject = REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["subject"]

    domain = REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["domain"]
    if REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["admin"]:
        to_emails.extend(REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["admin"])

    text = REMOVE_SERVICE_ACCOUNT_EMAIL_NOTIFICATION["content"]
    content = text.format(project_id)

    for email, removal_reasons in invalid_service_account_reasons.iteritems():
        if removal_reasons:
            content += "\n\t - Service account {} was removed from Google Project {}.".format(
                email, project_id
            )
            for reason in removal_reasons:
                content += "\n\t\t - {}".format(reason)

    general_project_errors = invalid_project_reasons.get("general")
    non_reg_sa_errors = invalid_project_reasons.get(
        "non_registered_service_accounts", {}
    )
    if general_project_errors or non_reg_sa_errors:
        content += (
            "\n\t - Google Project {} determined invalid. All service "
            "accounts with data access will be removed from access.".format(project_id)
        )
        for removal_reason in general_project_errors:
            if removal_reason:
                content += "\n\t\t - {}".format(removal_reason)

        if non_reg_sa_errors:
            for sa_email, removal_reasons in non_reg_sa_errors.iteritems():
                content += "\n\t\t - Google Project Service Account {} determined invalid.".format(
                    sa_email
                )
                for reason in removal_reasons:
                    content += "\n\t\t\t - {}".format(reason)

    return utils.send_email(from_email, to_emails, subject, content, domain)
