from fence.resources.google.validity import GoogleProjectValidity


class GoogleServiceAccountRegistration(object):
    """
    Helper class for certain functions in /google endpoints. Represents a registered
    service account and it's basic information. You can optionally include a user_id,
    which represents which user is interacting w/ or requesting changes for the
    given registered service account.
    """

    def __init__(self, email, project_access, google_project_id, user_id=None):
        """
        Return a GoogleServiceAccountRegistration instance

        Args:
            email(str): email address of
                service account to be registered
            google_project_id(str): unique-id of google project
            project_access(List[str]): list of project auth-ids which
                identify which projects the service account should have
                access to
            user_id (str, optional): Description
        """
        self.email = email
        self.project_access = project_access
        self.google_project_id = google_project_id
        self.user_id = user_id

    def get_project_validity(self, early_return=False):
        """
        Return the validity of the project if the current service account was
        attempted to be registered with the given project access by the provided user.

        Returns:
            fence.resources.google.validity.GoogleProjectValidity: Representation
                of the validity of the project after attempting regitration of the SA
        """
        project_validity = GoogleProjectValidity(
            google_project_id=self.google_project_id,
            new_service_account=self.email,
            new_service_account_access=self.project_access,
            user_id=self.user_id,
        )
        project_validity.check_validity(early_return=early_return)
        return project_validity
