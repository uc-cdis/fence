class RegisteredGoogleServiceAccount(object):
    """
    Helper class for certain functions in /google endpoints. Represents a registered
    service account and it's basic information. You can optionally include a user_id,
    which represents which user is interacting w/ or requesting changes for the
    given registered service account.
    """

    def __init__(self, email, project_access, google_project_id, user_id=None):
        """
        Return a RegisteredGoogleServiceAccount instance

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
