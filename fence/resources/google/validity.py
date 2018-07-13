"""
Objects with validity checking for Google service account registration.
"""
from collections import Mapping

from fence.resources.google.utils import (
    get_registered_service_accounts,
    get_project_access_from_service_accounts,
    get_user_ids_from_google_members,
    get_service_account_ids_from_google_project
)
from fence.resources.google.access_utils import (
    is_valid_service_account_type,
    service_account_has_external_access,
    is_service_account_from_google_project,
    google_project_has_parent_org,
    google_project_has_valid_membership,
    do_all_users_have_access_to_project
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
            'valid_parent_org': True,
            'valid_membership': True,
            'service_accounts': {
                'someaccount@something.com': {
                    'valid_type': True,
                    'no_external_access': True,
                    'owned_by_project': True
                },
                'other_service_account_in_project@something.com': {
                    'valid_type': True,
                    'no_external_access': True,
                    'owned_by_project': True
                }
            },
            'access': {
                'ProjectA': True,
                'ProjectB': False
            }
        }
    """
    def __init__(
            self, google_project_id,
            new_service_account=None,
            new_service_account_access=None,
            *args, **kwargs):
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
        """
        self.google_project_id = google_project_id
        self.new_service_account = new_service_account
        self.new_service_account_access = new_service_account_access or []
        super(GoogleProjectValidity, self).__init__(*args, **kwargs)

        # setup default values for error information, will get updated in
        # check_validity
        self._info['valid_parent_org'] = None
        self._info['valid_membership'] = None
        self._info['service_accounts'] = {}
        self._info['access'] = {}

    def check_validity(self, early_return=True):
        """
        Determine whether or not project is valid for registration. If
        early_return is False, this object will store information about the
        failure.

        Args:
            early_return (bool, optional): Description
        """
        valid_parent_org = (
            not google_project_has_parent_org(self.google_project_id)
        )
        self.set('valid_parent_org', valid_parent_org)
        if not valid_parent_org and early_return:
            return

        valid_membership = (
            google_project_has_valid_membership(self.google_project_id)
        )
        self.set('valid_membership', valid_membership)
        if not valid_membership and early_return:
            return

        service_accounts = (
            get_service_account_ids_from_google_project(self.google_project_id)
        )

        if self.new_service_account:
            service_accounts.append(self.new_service_account)

        # use a generic validityinfo object to hold all the service accounts
        # validity. then check all the service accounts. Top level will be
        # invalid if any service accounts are invalid
        service_accounts_validity = ValidityInfo()
        for service_account in service_accounts:
            service_account_validity_info = GoogleServiceAccountValidity(
                service_account, self.google_project_id
            )
            service_account_validity_info.check_validity(
                early_return=early_return
            )
            if not service_account_validity_info and early_return:
                return

            # update project with error info from the service accounts
            service_account_id = str(service_account)  # TODO should be email
            service_accounts_validity.set(
                service_account_id, service_account_validity_info)

        self.set('service_accounts', service_accounts_validity)

        # get the service accounts for the project to determine all the data
        # the project can access through the service accounts
        service_accounts = (
            get_registered_service_accounts(self.google_project_id)
        )
        service_account_access = (
            get_project_access_from_service_accounts(service_accounts)
        )

        # extend list with any provided access to test
        service_account_access.extend(self.new_service_account_access)

        # make sure all the users of the project actually have access to all
        # the data the service accounts have access to
        project_members = []  # TODO get all members on google project

        all_user_ids = get_user_ids_from_google_members(project_members)

        # use a generic validityinfo object to hold all the projects validity
        project_access_validity = ValidityInfo()
        for project in service_account_access:
            valid_access = do_all_users_have_access_to_project(
                all_user_ids, project)
            project_access_validity.set(str(project), valid_access)

        self.set('access', project_access_validity)


class GoogleServiceAccountValidity(ValidityInfo):
    """
    A representation of a Google Service Accounts's validity regarding
    registration for access to data.

    Example Usage and Information:

        sa_validity = (
            GoogleServiceAccountValidity(
                account_id='some-service-account@something.com'
                google_project_id='abc123',
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

    def __init__(self, account_id, google_project_id, *args, **kwargs):
        self.account_id = account_id
        self.google_project_id = google_project_id
        super(GoogleServiceAccountValidity, self).__init__(*args, **kwargs)

        # setup default values for error information, will get updated in
        # check_validity
        self._info['valid_type'] = None
        self._info['no_external_access'] = None
        self._info['owned_by_project'] = None

    def check_validity(self, early_return=True):
        valid_type = is_valid_service_account_type(self.account_id)
        self.set('valid_type', valid_type)
        if not valid_type and early_return:
            return

        no_external_access = not (
            service_account_has_external_access(self.account_id)
        )
        self.set('no_external_access', no_external_access)
        if not no_external_access and early_return:
            return

        is_owned_by_google_project = (
            is_service_account_from_google_project(
                self.account_id,
                self.google_project_id)
        )
        self.set('owned_by_project', is_owned_by_google_project)
        if not early_return and early_return:
            return
