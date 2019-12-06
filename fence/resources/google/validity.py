"""
Objects with validity checking for Google service account registration.
"""
from collections import Mapping
from fence.errors import NotFound

from fence.resources.google.utils import (
    get_registered_service_accounts_with_access,
    get_project_access_from_service_accounts,
    get_users_from_google_members,
    get_service_account_ids_from_google_members,
    is_google_managed_service_account,
)
from fence.resources.google.access_utils import (
    is_valid_service_account_type,
    service_account_has_external_access,
    is_service_account_from_google_project,
    get_google_project_membership,
    get_google_project_parent_org,
    get_google_project_valid_users_and_service_accounts,
    do_all_users_have_access_to_project,
    get_project_from_auth_id,
    get_google_project_number,
    get_service_account_policy,
    remove_white_listed_service_account_ids,
    is_org_whitelisted,
    is_user_member_of_google_project,
    is_user_member_of_all_google_projects,
)
from cirrus.google_cloud import GoogleCloudManager

from cdislogging import get_logger

logger = get_logger(__name__)


class ValidityInfo(Mapping):
    """
    A representation of validity of an item along with
    information about the validity.

    It's a dict-like object which can be evaulated as a boolean value.
    If the info is false-y, the validity of this object will evaluate to False.

    CAVEAT: None is allowed and will not make the validity False, this
            represents a validity check that was NOT run
            (e.g. we have no information)

    This means that you can nest ValidityInfo objects and
    the "valid" status of the parent object will always be updated when adding
    new validity information.
    """

    def __init__(self, default_validity=True):
        # innocent until proven guilty, default validity is True
        self._valid = default_validity
        self._info = {}

    def get(self, key, *args):
        return self._info.get(key, *args)

    def set(self, key, value):
        if not value and value is not None:
            self._valid = False
        self._info.__setitem__(key, value)

    def __setitem__(self, key, value):
        if not value and value is not None:
            self._valid = False
        self._info.__setitem__(key, value)

    def __contains__(self, key):
        return key in self._info

    def __iter__(self):
        for key, value in self._info.items():
            yield key, value

    def __getitem__(self, key):
        return self._info[key]

    def __delitem__(self, key):
        del self._info[key]

    def __len__(self):
        return len(self._info)

    def __bool__(self):
        return self._valid

    def __repr__(self):
        return str(self._info)

    def __str__(self):
        return str(self._info)

    def get_info(self):
        return self._info


class GoogleProjectValidity(ValidityInfo):
    """
    A representation of a Google Project's validity regarding service account
    registration for access to data.

    Example Usage and Information:

        project_validity = (
            GoogleProjectValidity(
                google_project_id='abc123',
                new_service_account='someaccount@something.com',
                new_service_account_access=['projectA', 'ProjectB']
            )
        )
        project_validity.check_validity(early_return=False)

        NOTE: project_validity can be evaluated as if it's a boolean and will
        be False if ANY of the values in the dict-like structure are False.
        In other words, a single invalid item will make the whole project
        invalid.

        An example of the dict-like structure with validity info is:

        {
            'monitor_has_access': True,
            'valid_parent_org': True,
            'valid_membership': True,
            'new_service_account': {
                'account@something.com': {
                    'valid_type': True,
                    'no_external_access': True,
                    'owned_by_project': True,
                    'exists': True
                },
            }
            'service_accounts': {
                'someaccount@something.com': {
                    'valid_type': None,
                    'no_external_access': True,
                    'owned_by_project': True,
                    'exists': True
                },
                'other_service_account_in_project@something.com': {
                    'valid_type': None,
                    'no_external_access': True,
                    'owned_by_project': True,
                    'exists': True
                }
            },
            'access': {
                'ProjectA': {
                    'exists': True,
                    'all_users_have_access': True
                },
                'ProjectB': {
                    'exists': True,
                    'all_users_have_access': True
                },
            }
        }
    """

    def __init__(
        self,
        google_project_id,
        new_service_account=None,
        new_service_account_access=None,
        user_id=None,
        google_cloud_manager=None,
        *args,
        **kwargs
    ):
        """
        Initialize

        Args:
            google_project_id (str): Google project identifier
            new_service_account (str, optional): an additional service account
                identifier (ex: email) to include when checking access. You can
                provide this without actually giving it access to check if
                access will be valid
            new_service_account_access (List(str), optional): List of
                Project.auth_ids to attempt to provide the new service account
                access to
            user_id (None, optional): User requesting validation. ONLY pass this if you
                want to check if the user is a member of this project.
        """
        self.google_project_id = google_project_id
        self.new_service_account = new_service_account
        self.new_service_account_access = new_service_account_access or []
        self.user_id = user_id
        self.google_cloud_manager = google_cloud_manager or GoogleCloudManager(
            google_project_id
        )

        super(GoogleProjectValidity, self).__init__(*args, **kwargs)

        # setup default values for error information, will get updated in
        # check_validity
        self._info["user_has_access"] = None
        self._info["monitor_has_access"] = None
        self._info["valid_parent_org"] = None
        self._info["valid_member_types"] = None
        self._info["members_exist_in_fence"] = None
        self._info["new_service_account"] = {}
        self._info["service_accounts"] = {}
        self._info["access"] = {}

    def check_validity(self, early_return=True, db=None):
        """
        Determine whether or not project is valid for registration. If
        early_return is False, this object will store information about the
        failure.

        Args:
            early_return (bool, optional): Description
        """

        self.google_cloud_manager.open()

        logger.debug(
            "Google Project with id: {}, "
            "new service account requested: {}, project access requested: {}, "
            "user requesting: {}".format(
                self.google_project_id,
                self.new_service_account,
                self.new_service_account_access,
                self.user_id,
            )
        )

        logger.debug(
            "Attempting to get project number "
            "for project id {}".format(self.google_project_id)
        )
        google_project_number = get_google_project_number(
            self.google_project_id, self.google_cloud_manager
        )
        has_access = bool(google_project_number)

        self.set("monitor_has_access", has_access)
        # always early return if we can't access the project
        if not has_access:
            logger.warning(
                "INVALID Fence's Monitoring service account does "
                "NOT have access in project id {}. Monitor needs access to continue "
                "checking project validity. Exiting early and determining invalid.".format(
                    self.google_project_id
                )
            )
            return

        logger.debug(
            "Retrieving project membership "
            "for project id {}".format(self.google_project_id)
        )
        membership = get_google_project_membership(
            self.google_project_id, self.google_cloud_manager
        )
        logger.debug(
            "Project Members: {}".format(
                str(
                    [
                        getattr(member, "email_id", "unknown_member_email")
                        for member in membership
                    ]
                )
            )
        )

        if self.user_id is not None:
            logger.debug(
                "Checking that user requesting, {}, is part of "
                "the Google Project with id {}".format(
                    self.user_id, self.google_project_id
                )
            )
            user_has_access = is_user_member_of_google_project(
                self.user_id, self.google_cloud_manager, membership=membership, db=db
            )
            self.set("user_has_access", user_has_access)
            if not user_has_access:
                # always early return if user isn't a member on the project
                logger.warning(
                    "INVALID User {} "
                    "for project id {}. User is not a member of the project so does not "
                    "have permission on the project.".format(
                        self.user_id, self.google_project_id
                    )
                )
                return

        logger.debug(
            "Retrieving Parent Organization "
            "for project id {} to make sure it's valid".format(self.google_project_id)
        )
        parent_org = get_google_project_parent_org(self.google_cloud_manager)
        valid_parent_org = True

        if parent_org:
            valid_parent_org = is_org_whitelisted(parent_org)

        self.set("valid_parent_org", valid_parent_org)

        if not valid_parent_org:
            logger.warning(
                "INVALID Parent Organization {} "
                "for project id {}. No parent org is allowed unless it's explicitly "
                "whitelisted in cfg.".format(parent_org, self.google_project_id)
            )
            if early_return:
                return

        logger.debug(
            "Determining if other users and service accounts on "
            "project id {} are valid.".format(self.google_project_id)
        )
        user_members = None
        service_account_members = []
        try:
            (
                user_members,
                service_account_members,
            ) = get_google_project_valid_users_and_service_accounts(
                self.google_project_id, self.google_cloud_manager, membership=membership
            )
            self.set("valid_member_types", True)
        except Exception:
            self.set("valid_member_types", False)
            logger.warning(
                "INVALID users and/or service accounts (SAs) on "
                "project id {}.".format(self.google_project_id)
            )
            if early_return:
                return

        logger.debug(
            "Determining if valid users exist in fence.".format(self.google_project_id)
        )
        # if we have valid members, we can check if they exist in fence
        users_in_project = None
        if user_members is not None:
            try:
                users_in_project = get_users_from_google_members(user_members, db=db)
                self.set("members_exist_in_fence", True)
            except Exception as e:
                self.set("members_exist_in_fence", False)
                logger.warning(
                    "INVALID user(s) do not exist in fence and thus, "
                    "we cannot determine their authZ info: {}.".format(e)
                )
                if early_return:
                    return

        # use a generic validityinfo object to hold all the service accounts
        # validity. then check all the service accounts. Top level will be
        # invalid if any service accounts are invalid
        new_service_account_validity = ValidityInfo()
        if self.new_service_account:
            service_account_validity_info = GoogleServiceAccountValidity(
                self.new_service_account,
                self.google_project_id,
                google_project_number=google_project_number,
                google_cloud_manager=self.google_cloud_manager,
            )

            service_account_id = str(self.new_service_account)

            logger.debug(
                "Google Project with id: {} and number: {}. "
                "Beginning validation on service account for registration {}".format(
                    self.google_project_id, google_project_number, service_account_id
                )
            )

            logger.debug(
                "Determining if the service account {} is google-managed.".format(
                    service_account_id
                )
            )
            # we do NOT need to check the service account type and external access
            # for google-managed accounts.
            if is_google_managed_service_account(service_account_id):
                logger.debug(
                    "GCP SA Validity -Service account {} IS google-managed. Therefore, "
                    "we do NOT need to check the SA Type or if it has external access.".format(
                        service_account_id
                    )
                )
                service_account_validity_info.check_validity(
                    early_return=early_return,
                    check_type=True,
                    check_policy_accessible=True,
                    check_external_access=False,
                )
            else:
                logger.debug(
                    "GCP SA Validity -Service account {} is NOT google-managed. Therefore, "
                    "we need to run all validation checks against it.".format(
                        service_account_id
                    )
                )
                service_account_validity_info.check_validity(
                    early_return=early_return,
                    check_type=True,
                    check_policy_accessible=True,
                    check_external_access=True,
                )

            # update project with error info from the service accounts
            new_service_account_validity.set(
                service_account_id, service_account_validity_info
            )

            if not service_account_validity_info:
                logger.warning("INVALID service account {}.".format(service_account_id))
                # if we need to return early for invalid SA, make sure to include
                # error details and invalidate the overall validity
                if early_return:
                    self.set("new_service_account", new_service_account_validity)
                    return

        self.set("new_service_account", new_service_account_validity)

        logger.debug(
            "Google Project with id: {} and number: {}. "
            "Beginning validation on project service accounts not requested for "
            "registration.".format(self.google_project_id, google_project_number)
        )

        service_accounts = get_service_account_ids_from_google_members(
            service_account_members
        )

        logger.debug("SAs on the project {}.".format(service_accounts))

        remove_white_listed_service_account_ids(service_accounts)

        # don't double check service account being registered
        if self.new_service_account:
            try:
                service_accounts.remove(self.new_service_account)
            except ValueError:
                logger.debug(
                    "Service Account requested for registration is not a "
                    "member of the Google project."
                )

        # use a generic validityinfo object to hold all the service accounts
        # validity. then check all the service accounts. Top level will be
        # invalid if any service accounts are invalid
        service_accounts_validity = ValidityInfo()
        for service_account in service_accounts:
            service_account_validity_info = self._get_project_sa_validity_info(
                service_account, google_project_number, early_return
            )

            # update project with error info from the service accounts
            service_accounts_validity.set(
                service_account, service_account_validity_info
            )

            if not service_account_validity_info and early_return:
                # if we need to return early for invalid SA, make sure to include
                # error details and invalidate the overall validity
                self.set("service_accounts", service_accounts_validity)
                return

        self.set("service_accounts", service_accounts_validity)

        logger.debug(
            "Checking data access for Google Project {}...".format(
                self.google_project_id
            )
        )

        # get the service accounts for the project to determine all the data
        # the project can access through the service accounts
        service_accounts = get_registered_service_accounts_with_access(
            self.google_project_id, db=db
        )

        # don't double check service account being updated if it was previously registered
        # in other words, this may be an update of existing access (from A&B to just A)
        # so we need to ONLY validate the new access (which happens below when the project
        # access list is extended with new access requested)
        if self.new_service_account:
            logger.debug(
                "Removing new/updated SA {} from list of existing SAs in order "
                "to only validate the newly requested access.".format(
                    self.new_service_account
                )
            )
            service_accounts = [
                sa
                for sa in service_accounts
                if sa.email.lower() != str(self.new_service_account).lower()
            ]

        service_account_project_access = get_project_access_from_service_accounts(
            service_accounts, db=db
        )

        logger.debug(
            "Registered SAs {} current have project access: {}".format(
                [sa.email for sa in service_accounts], service_account_project_access
            )
        )

        # use a generic validityinfo object to hold all the projects validity
        project_access_validities = ValidityInfo()

        # extend list with any provided access to test
        for provided_access in self.new_service_account_access:
            project = get_project_from_auth_id(provided_access)

            # if provided access doesn't exist, set error in project_validity
            if not project:
                logger.warning(
                    "INVALID project access requested. "
                    "Data Access with auth_id {} does not exist.".format(
                        provided_access
                    )
                )
                project_validity = ValidityInfo()
                project_validity.set("exists", False)
                project_validity.set("all_users_have_access", None)
                project_access_validities.set(str(provided_access), project_validity)
            else:
                service_account_project_access.append(project)

        logger.debug(
            "New project access requested (in addition to "
            "previous access): {}.".format(service_account_project_access)
        )

        # make sure all the users of the project actually have access to all
        # the data the service accounts have access to
        for project in service_account_project_access:
            project_validity = ValidityInfo()
            project_validity.set("exists", True)

            # if all the users exist in our db, we can check if they have valid
            # access
            logger.debug(
                "Checking that all users in project have "
                "access to project with id {}".format(
                    getattr(project, "id", "ERROR-could-not-get-project-id")
                )
            )
            valid_access = None
            if users_in_project:
                valid_access = do_all_users_have_access_to_project(
                    users_in_project, project.id, db=db
                )
                if not valid_access:
                    logger.warning(
                        "INVALID Some users do NOT have "
                        "access to project with id {}. users in project: {}".format(
                            getattr(project, "id", "ERROR-could-not-get-project-id"),
                            [
                                getattr(user, "username", "unknown_user")
                                for user in users_in_project
                            ],
                        )
                    )

            project_validity.set("all_users_have_access", valid_access)

            project_access_validities.set(str(project.auth_id), project_validity)

        self.set("access", project_access_validities)
        self.google_cloud_manager.close()
        return

    def _get_project_sa_validity_info(
        self, service_account, google_project_number, early_return
    ):
        service_account_id = str(service_account)

        service_account_validity_info = GoogleServiceAccountValidity(
            service_account,
            self.google_project_id,
            google_project_number=google_project_number,
            google_cloud_manager=self.google_cloud_manager,
        )

        logger.debug(
            "Google Project with id: {} and number: {}. "
            "Beginning validation on project service account {}".format(
                self.google_project_id, google_project_number, service_account_id
            )
        )

        logger.debug(
            "Determining if the service account {} is google-managed.".format(
                service_account_id
            )
        )

        # we do NOT need to check the service account type and external access
        # for google-managed accounts.
        if is_google_managed_service_account(service_account_id):
            logger.debug(
                "Service account {} IS google-managed. Therefore, "
                "we only need to detemine if it belongs.".format(service_account_id)
            )
            service_account_validity_info.check_validity(
                early_return=early_return,
                check_type=False,
                check_policy_accessible=False,
                check_external_access=False,
            )
        else:
            logger.debug(
                "Service account {} is NOT google-managed. Therefore, "
                "we need to run all validation checks against it.".format(
                    service_account_id
                )
            )
            service_account_validity_info.check_validity(
                early_return=early_return,
                check_type=True,
                check_policy_accessible=True,
                check_external_access=True,
            )

        return service_account_validity_info


class GoogleServiceAccountValidity(ValidityInfo):
    """
    A representation of a Google Service Accounts's validity regarding
    registration for access to data.

    Example Usage and Information:

        sa_validity = (
            GoogleServiceAccountValidity(
                account_id='some-service-account@something.com'
                google_project_id='abc123',
                google_project_number='123456789'
            )
        )
        sa_validity.check_validity(early_return=False)

        NOTE: sa_validity can be evaluated as if it's a boolean and will
        be False if ANY of the values in the dict-like structure are False.
        In other words, a single invalid item will make the whole project
        invalid.

        An example of the dict-like structure with validity info is:

        {
            'valid_type': True,
            'no_external_access': True,
            'owned_by_project': True,
            'exists': True
        }
    """

    def __init__(
        self,
        account_id,
        google_project_id,
        google_cloud_manager=None,
        google_project_number=None,
        *args,
        **kwargs
    ):
        self.account_id = account_id
        self.google_project_id = google_project_id

        # default to the given project id if not provided
        self.google_project_number = google_project_number or google_project_id
        self.google_cloud_manager = google_cloud_manager or GoogleCloudManager(
            google_project_id
        )
        super(GoogleServiceAccountValidity, self).__init__(*args, **kwargs)

        # setup default values for error information, will get updated in
        # check_validity
        self._info["owned_by_project"] = None
        self._info["valid_type"] = None
        self._info["no_external_access"] = None
        self._info["policy_accessible"] = None

    def check_validity(
        self,
        early_return=True,
        check_type=True,
        check_external_access=True,
        check_policy_accessible=True,
    ):
        logger.debug(
            "Validating Google Service Account {} for Google Project {}.".format(
                self.account_id, self.google_project_id
            )
        )

        self.google_cloud_manager.open()

        # check ownership
        logger.debug(
            "Determining if {} is owned by the Google Project.".format(self.account_id)
        )

        is_owned_by_google_project = is_service_account_from_google_project(
            self.account_id, self.google_project_id, self.google_project_number
        )
        self.set("owned_by_project", is_owned_by_google_project)
        if not is_owned_by_google_project:
            logger.warning(
                "INVALID SA {}, it is NOT owned by the Google Project {}.".format(
                    self.account_id, self.google_project_id
                )
            )
            if early_return:
                self.google_cloud_manager.close()
                return

        # select the GCM to use for the remainder of the checks
        # if the account is not owned by the google project then
        # it is invalid, however, if Fence has access to the SA's
        # project, we can still check the other conditions

        if is_owned_by_google_project:
            gcm = self.google_cloud_manager
        else:
            self.google_cloud_manager.close()
            try:
                # check to see if we can access the project the SA belongs to
                project_id = self.account_id.split("@")[-1].split(".")[0]
                gcm = GoogleCloudManager(project_id)
                gcm.open()
            except Exception:
                logger.debug(
                    "Could not access the Google Project for Service "
                    "Account {}. Unable to continue validity "
                    "checkingwithout access to the project, "
                    "early exit.".format(self.account_id)
                )
                return

        # check if the SA's policy is accessible
        policy_accessible = None
        sa_policy = None
        if check_policy_accessible:
            try:
                policy_accessible = True
                sa_policy = get_service_account_policy(self.account_id, gcm)
            except Exception:
                policy_accessible = False
                gcm.close()
                return
            finally:
                self.set("policy_accessible", policy_accessible)

        if check_external_access:

            if not policy_accessible:
                logger.warning(
                    "Invalid function use. External Access check requires "
                    "Service Account Policy & may fail if policy is not "
                    "accessible. If you want to check external access, make "
                    "sure you are also checking policy_accessible. "
                )
                gcm.close()
                return

            no_external_access = not (
                service_account_has_external_access(self.account_id, gcm, sa_policy)
            )
            self.set("no_external_access", no_external_access)
            if not no_external_access:
                logger.warning(
                    "INVALID SA {}, it has external access "
                    "(keys generated or roles on it).".format(self.account_id)
                )
                if early_return:
                    gcm.close()
                    return

        # check if the SA is an allowed type
        if check_type:

            if not policy_accessible:
                logger.warning(
                    "Policy access was not checked. If the service account's "
                    "policy is not accessible or the service account does not "
                    "exist, this check may fail."
                )
                # don't return early, we can still check type without checking
                # policy, however, if the SA doesn't exist, this will fail

            valid_type = is_valid_service_account_type(self.account_id, gcm)

            self.set("valid_type", valid_type)
            if not valid_type:
                logger.warning(
                    "INVALID SA {}, it is not a valid SA type.".format(self.account_id)
                )
                if early_return:
                    gcm.close()
                    return

        gcm.close()
