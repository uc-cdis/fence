from fence.resources.storage.storageclient.base import StorageClient
from fence.resources.storage.storageclient.errors import RequestError
from gen3cirrus import GoogleCloudManager


class UserProxy(object):
    def __init__(self, username):
        self.username = username


class GoogleCloudStorageClient(StorageClient):
    def __init__(self, config):
        super(GoogleCloudStorageClient, self).__init__(__name__)
        self._config = config
        self.google_project_id = config.get("google_project_id")

    @property
    def provider(self):
        """
        Returns the type of storage
        """
        return "GoogleCloudStorage"

    def get_user(self, username):
        """
        Get a user

        Args:
            username (str): An email address representing a User's Google
               Proxy Group (e.g. a single Google Group to hold a single
               user's diff identities).

        Returns:
            UserProxy: a UserProxy object if the user exists, else None
        """
        user_proxy = None

        with GoogleCloudManager(project_id=self.google_project_id) as g_mgr:
            user_proxy_response = g_mgr.get_group(username)
            if user_proxy_response.get("email"):
                user_proxy = UserProxy(username=user_proxy_response.get("email"))

        return user_proxy

    def delete_user(self, username):
        """
        Delete a user
        :returns: None
        :raise:
            :NotFound: the user is not found
        """
        msg = "delete_user not implemented"
        raise NotImplementedError(msg)

    def create_user(self, username):
        """
        Create a user
        :returns: User object
        """
        msg = "create_user not implemented"
        raise NotImplementedError(msg)

    def list_users(self):
        """
        List users
        :returns: a list of User objects
        """
        msg = "list_users not implemented"
        raise NotImplementedError(msg)

    def get_or_create_user(self, username):
        """
        Tries to retrieve a user.

        WARNING: If the user is not found, this DOES NOT CREATE ONE.

        Google architecture requires that a separate process populate
        a proxy Google group per user. If it doesn't exist, we can't create it
        here.
        """
        user_proxy = self.get_user(username)
        if not user_proxy:
            raise Exception(
                "Unable to determine User's Google Proxy group. Cannot create "
                "here. Another process should create proxy groups for "
                "new users. Username provided: {}".format(username)
            )

        return user_proxy

    def create_keypair(self, username):
        """
        Creates a keypair for the user, and
        returns it
        """
        msg = "create_keypair not implemented"
        raise NotImplementedError(msg)

    def delete_keypair(self, username, access_key):
        """
        Deletes a keypair from the user and
        doesn't return anything
        """
        msg = "delete_keypair not implemented"
        raise NotImplementedError(msg)

    def add_bucket_acl(self, bucket, username, access=None):
        """
        Tries to grant a user access to a bucket

        Args:
            bucket (str): Google Bucket Access Group email address. This should
                be the address of a Google Group that has read access on a
                single bucket. Access is controlled by adding members to this
                group.
            username (str): An email address of a member to add to the Google
                Bucket Access Group.
            access (str): IGNORED. For Google buckets, the Google Bucket Access
                Group is given access to the bucket through Google's
                IAM, so you cannot selectively choose permissions. Once you're
                added, you have the access that was set up for that group
                in Google IAM.
        """
        response = None
        with GoogleCloudManager(project_id=self.google_project_id) as g_mgr:
            try:
                response = g_mgr.add_member_to_group(
                    member_email=username, group_id=bucket
                )
            except Exception as exc:
                raise RequestError("Google API Error: {}".format(exc), code=400)

        return response

    def has_bucket_access(self, bucket, user_id):
        """
        Check if the user appears in the acl
        : returns Bool
        """
        msg = "has_bucket_access not implemented"
        raise NotImplementedError(msg)

    def list_buckets(self):
        """
        Return a list of Bucket objects
        : [bucket1, bucket2,...]
        """
        msg = "list_buckets not implemented"
        raise NotImplementedError(msg)

    def delete_all_keypairs(self, user):
        """
        Remove all the keys from a user
        : returns None
        """
        msg = "delete_all_keypairs not implemented"
        raise NotImplementedError(msg)

    def get_bucket(self, bucket):
        """
        Return a bucket from the storage
        """
        msg = "get_bucket not implemented"
        raise NotImplementedError(msg)

    def get_or_create_bucket(self, bucket, access_key=None, secret_key=None):
        """
        Tries to retrieve a bucket and if fit fails,
        creates and returns one
        """
        msg = "get_or_create_bucket not implemented"
        raise NotImplementedError(msg)

    def edit_bucket_template(self, template_id, **kwargs):
        """
        Change the parameters for the template used to create
        the buckets
        """
        msg = "edit_bucket_template not implemented"
        raise NotImplementedError(msg)

    def update_bucket_acl(self, bucket, user_list):
        """
        Add acl's for the list of users
        """
        msg = "update_bucket_acl not implemented"
        raise NotImplementedError(msg)

    def set_bucket_quota(self, bucket, quota_unit, quota):
        """
        Set quota for the entire bucket
        """
        msg = "set_bucket_quota not implemented"
        raise NotImplementedError(msg)

    def delete_bucket_acl(self, bucket, user):
        """
        Set quota for the entire bucket

        Args:
            bucket (str): Google Bucket Access Group email address. This should
                be the address of a Google Group that has read access on a
                single bucket. Access is controlled by adding members to this
                group.
            user (str): An email address of a member to add to the Google
                Bucket Access Group.
        """
        response = None
        with GoogleCloudManager(project_id=self.google_project_id) as g_mgr:
            try:
                response = g_mgr.remove_member_from_group(
                    member_email=user, group_id=bucket
                )
            except Exception as exc:
                raise RequestError("Google API Error: {}".format(exc), code=400)

        return response
