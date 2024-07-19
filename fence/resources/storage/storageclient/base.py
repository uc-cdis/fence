from abc import abstractmethod, abstractproperty, ABCMeta
from .errors import ClientSideError
import logging
from cdislogging import get_logger


def handle_request(fun):
    """
    Exception treatment for the REST API calls
    """

    def wrapper(self, *args, **kwargs):
        """
        We raise an exception when
        the code on the client side fails
        Server side errors are taken care of
        through response codes
        """
        try:
            return fun(self, *args, **kwargs)
        except Exception as req_exception:
            self.logger.exception("internal error")
            raise ClientSideError(str(req_exception))

    return wrapper


class StorageClient(object, metaclass=ABCMeta):
    """Abstract storage client class"""

    def __init__(self, cls_name):
        self.logger = get_logger(cls_name)
        self.logger.setLevel(logging.DEBUG)

    @abstractproperty
    def provider(self):
        """
        Name of the storage provider. eg: ceph
        """
        msg = "Provider not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def get_user(self, username):
        """
        Get a user
        :returns: a User object if the user exists, else None
        """
        msg = "get_user not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def delete_user(self, username):
        """
        Delete a user
        :returns: None
        :raise:
            :NotFound: the user is not found
        """
        msg = "delete_user not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def create_user(self, username):
        """
        Create a user
        :returns: User object
        """
        msg = "create_user not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def list_users(self):
        """
        List users
        :returns: a list of User objects
        """
        msg = "list_users not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def get_or_create_user(self, username):
        """
        Tries to retrieve a user.
        If the user is not found, a new one
        is created and returned
        """
        msg = "get_or_create_user not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def create_keypair(self, username):
        """
        Creates a keypair for the user, and
        returns it
        """
        msg = "create_keypair not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def delete_keypair(self, username, access_key):
        """
        Deletes a keypair from the user and
        doesn't return anything
        """
        msg = "delete_keypair not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def add_bucket_acl(self, bucket, username, access=None):
        """
        Tries to grant a user access to a bucket
        """
        msg = "add_bucket_acl not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def has_bucket_access(self, bucket, user_id):
        """
        Check if the user appears in the acl
        : returns Bool
        """
        msg = "has_bucket_access not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def list_buckets(self):
        """
        Return a list of Bucket objects
        : [bucket1, bucket2,...]
        """
        msg = "list_buckets not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def delete_all_keypairs(self, user):
        """
        Remove all the keys from a user
        : returns None
        """
        msg = "delete_all_keypairs not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def get_bucket(self, bucket):
        """
        Return a bucket from the storage
        """
        msg = "get_bucket not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def get_or_create_bucket(self, bucket, access_key=None, secret_key=None):
        """
        Tries to retrieve a bucket and if fit fails,
        creates and returns one
        """
        msg = "get_or_create_bucket not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def get_bucket(self, bucket, access_key=None, secret_key=None):
        """
        Tries to retrieve a bucket and if fit fails,
        creates and returns one
        """
        msg = "get_bucket not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def edit_bucket_template(self, template_id, **kwargs):
        """
        Change the parameters for the template used to create
        the buckets
        """
        msg = "edit_bucket_template not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def update_bucket_acl(self, bucket, user_list):
        """
        Add acl's for the list of users
        """
        msg = "update_bucket_acl not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def set_bucket_quota(self, bucket, quota_unit, quota):
        """
        Set quota for the entire bucket
        """
        msg = "set_bucket_quota not implemented"
        raise NotImplementedError(msg)

    @abstractmethod
    def delete_bucket_acl(self, bucket, user):
        """
        Set quota for the entire bucket
        """
        msg = "delete_bucket_acl not implemented"
        raise NotImplementedError(msg)


class User(object):
    def __init__(self, username):
        """
        - permissions {'bucketname': 'PERMISSION'}
        - keys [{'access_key': abc,'secret_key': 'def'}]
        """
        self.username = username
        self.permissions = {}
        self.keys = []
        self.id = None


class Bucket(object):
    def __init__(self, name, bucket_id, quota):
        """
        Simple bucket representation
        Quota is in TiBs or such units
        """
        self.name = name
        self.id = bucket_id
        self.quota = quota
