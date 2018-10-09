"""
Objects with validity checking for Google service account registration.
"""
from collections import Mapping

from fence.resources.google.utils import (
    get_registered_service_accounts,
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
    remove_white_listed_service_account_ids,
    is_org_whitelisted,
    is_user_member_of_all_google_projects,
)


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
        for key, value in self._info.iteritems():
            yield key, value

    def __getitem__(self, key):
        return self._info[key]

    def __delitem__(self, key):
        del self._info[key]

    def __len__(self):
        return len(self._info)

    def __bool__(self):
        return self._valid

    def __nonzero__(self):
        return self._valid

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
                    'owned_by_project': True
                },
            }
            'service_accounts': {
                'someaccount@something.com': {
                    'valid_type': None,
                    'no_external_access': True,
                    'owned_by_project': True
                },
                'other_service_account_in_project@something.com': {
                    'valid_type': None,
                    'no_external_access': True,
                    'owned_by_project': True
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

    def check_validity(self, early_return=True, db=None, config=None):
        """
        Determine whether or not project is valid for registration. If
        early_return is False, this object will store information about the
        failure.

        Args:
            early_return (bool, optional): Description
        """
        google_project_number = get_google_project_number(self.google_project_id)
        has_access = bool(google_project_number)

        self.set("monitor_has_access", has_access)
        # always early return if we can't access the project
        if not has_access:
            return

        membership = get_google_project_membership(self.google_project_id)

        if self.user_id is not None:
            user_has_access = is_user_member_of_all_google_projects(
                self.user_id, [self.google_project_id], membership=membership, db=db
            )
            self.set("user_has_access", user_has_access)
            if not user_has_access:
                # always early return if user isn't a member on the project
                return

        parent_org = get_google_project_parent_org(self.google_project_id)
        valid_parent_org = True

        # if there is an org, let's remove whitelisted orgs and then check validity
        # again
        white_listed_google_parent_orgs = (
            config.get("WHITE_LISTED_GOOGLE_PARENT_ORGS") if config else None
        )

        if parent_org:
            valid_parent_org = is_org_whitelisted(
                parent_org,
                white_listed_google_parent_orgs=white_listed_google_parent_orgs,
            )

        self.set("valid_parent_org", valid_parent_org)

        if not valid_parent_org and early_return:
            return

        user_members = None
        service_account_members = []
        try:
            user_members, service_account_members = get_google_project_valid_users_and_service_accounts(
                self.google_project_id, membership=membership
            )
            self.set("valid_member_types", True)
        except Exception:
            self.set("valid_member_types", False)
            if early_return:
                return

        # if we have valid members, we can check if they exist in fence
        users_in_project = None
        if user_members is not None:
            try:
                users_in_project = get_users_from_google_members(user_members, db=db)
                self.set("members_exist_in_fence", True)
            except Exception:
                self.set("members_exist_in_fence", False)
                if early_return:
                    return

        # use a generic validityinfo object to hold all the service accounts
        # validity. then check all the service accounts. Top level will be
        # invalid if any service accounts are invalid
        new_service_account_validity = ValidityInfo()
        if self.new_service_account:
            service_account_validity_info = GoogleServiceAccountValidity(
                self.new_service_account, self.google_project_id, google_project_number
            )

            service_account_id = str(self.new_service_account)

            google_sa_domains = (
                config.get("GOOGLE_MANAGED_SERVICE_ACCOUNT_DOMAINS") if config else None
            )
            # we do NOT need to check the service account type and external access
            # for google-managed accounts.
            if is_google_managed_service_account(
                service_account_id,
                google_managed_service_account_domains=google_sa_domains,
            ):
                service_account_validity_info.check_validity(
                    early_return=early_return,
                    check_type_and_access=False,
                    config=config,
                )
            else:
                service_account_validity_info.check_validity(
                    early_return=early_return, check_type_and_access=True, config=config
                )

            # update project with error info from the service accounts
            new_service_account_validity.set(
                service_account_id, service_account_validity_info
            )

            if not service_account_validity_info and early_return:
                # if we need to return early for invalid SA, make sure to include
                # error details and invalidate the overall validity
                self.set("new_service_account", new_service_account_validity)
                return

        self.set("new_service_account", new_service_account_validity)

        service_accounts = get_service_account_ids_from_google_members(
            service_account_members
        )

        white_listed_service_accounts = (
            config.get("WHITE_LISTED_SERVICE_ACCOUNT_EMAILS") if config else None
        )
        app_creds_file = (
            config.get("GOOGLE_APPLICATION_CREDENTIALS") if config else None
        )

        remove_white_listed_service_account_ids(
            service_accounts,
            app_creds_file=app_creds_file,
            white_listed_sa_emails=white_listed_service_accounts,
        )

        # use a generic validityinfo object to hold all the service accounts
        # validity. then check all the service accounts. Top level will be
        # invalid if any service accounts are invalid
        service_accounts_validity = ValidityInfo()
        for service_account in service_accounts:
            service_account_id = str(service_account)

            service_account_validity_info = GoogleServiceAccountValidity(
                service_account, self.google_project_id, google_project_number
            )

            google_sa_domains = (
                config.get("GOOGLE_MANAGED_SERVICE_ACCOUNT_DOMAINS") if config else None
            )
            # we do NOT need to check the service account type and external access
            # for google-managed accounts.
            if is_google_managed_service_account(
                service_account_id,
                google_managed_service_account_domains=google_sa_domains,
            ):
                service_account_validity_info.check_validity(
                    early_return=early_return,
                    check_type_and_access=False,
                    config=config,
                )
            else:
                service_account_validity_info.check_validity(
                    early_return=early_return, check_type_and_access=True, config=config
                )

            # update project with error info from the service accounts
            service_accounts_validity.set(
                service_account_id, service_account_validity_info
            )

            if not service_account_validity_info and early_return:
                # if we need to return early for invalid SA, make sure to include
                # error details and invalidate the overall validity
                self.set("service_accounts", service_accounts_validity)
                return

        self.set("service_accounts", service_accounts_validity)

        # get the service accounts for the project to determine all the data
        # the project can access through the service accounts
        service_accounts = get_registered_service_accounts(
            self.google_project_id, db=db
        )
        service_account_project_access = get_project_access_from_service_accounts(
            service_accounts, db=db
        )

        # use a generic validityinfo object to hold all the projects validity
        project_access_validities = ValidityInfo()

        # extend list with any provided access to test
        for provided_access in self.new_service_account_access:
            project = get_project_from_auth_id(provided_access)

            # if provided access doesn't exist, set error in project_validity
            if not project:
                project_validity = ValidityInfo()
                project_validity.set("exists", False)
                project_validity.set("all_users_have_access", None)
                project_access_validities.set(str(provided_access), project_validity)
            else:
                service_account_project_access.append(project)

        # make sure all the users of the project actually have access to all
        # the data the service accounts have access to
        for project in service_account_project_access:
            project_validity = ValidityInfo()
            project_validity.set("exists", True)

            # if all the users exist in our db, we can check if they have valid
            # access
            valid_access = None
            if users_in_project:
                valid_access = do_all_users_have_access_to_project(
                    users_in_project, project.id, db=db
                )
            project_validity.set("all_users_have_access", valid_access)

            project_access_validities.set(str(project.auth_id), project_validity)

        self.set("access", project_access_validities)
        return


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
            'owned_by_project': True
        }
    """

    def __init__(
        self, account_id, google_project_id, google_project_number=None, *args, **kwargs
    ):
        self.account_id = account_id
        self.google_project_id = google_project_id

        # default to the given project id if not provided
        self.google_project_number = google_project_number or google_project_id
        super(GoogleServiceAccountValidity, self).__init__(*args, **kwargs)

        # setup default values for error information, will get updated in
        # check_validity
        self._info["owned_by_project"] = None
        self._info["valid_type"] = None
        self._info["no_external_access"] = None

    def check_validity(
        self, early_return=True, check_type_and_access=True, config=None
    ):
        google_managed_sa_domains = (
            config["GOOGLE_MANAGED_SERVICE_ACCOUNT_DOMAINS"] if config else None
        )

        is_owned_by_google_project = is_service_account_from_google_project(
            self.account_id,
            self.google_project_id,
            self.google_project_number,
            google_managed_sa_domains=google_managed_sa_domains,
        )
        self.set("owned_by_project", is_owned_by_google_project)
        if not is_owned_by_google_project:
            # we cannot determine further information if the account isn't
            # owned by the project
            return

        if check_type_and_access:
            valid_type = is_valid_service_account_type(
                self.google_project_id, self.account_id
            )

            self.set("valid_type", valid_type)
            if not valid_type and early_return:
                return

            no_external_access = not (
                service_account_has_external_access(
                    self.account_id, self.google_project_id
                )
            )
            self.set("no_external_access", no_external_access)
            if not no_external_access and early_return:
                return
