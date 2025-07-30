"""
This module provides the necessary methods
for mocking the module
userapi.resources.storageclient.__init__.py
modules operations
"""
import unittest, random, string
from mock import patch
from fence.resources.storage.storageclient.base import User, Bucket
from fence.resources.storage.storageclient.errors import NotFoundError, RequestError


def get_client(config, backend):
    if backend in ["cleversafe", "google"]:
        return StorageClientMocker(backend)
    else:
        raise NotImplementedError()


class StorageClientMocker(object):
    """
    This class will contain the methods and
    the state of the mocking object. It is
    supposed to be modifiable by the very calls
    it is mocking
    """

    def __init__(self, provider, users={}, buckets={}, permisions={}):
        """
        users = {'Name1': User1, 'Name2': User2...}
        buckets = {'Name1': Bucket1, 'Name2': Bucket2...}
        """
        self.users = users
        self.buckets = buckets
        self.provider = provider
        self.user_counter = 0
        self.bucket_counter = 0

    def provider(self):
        """
        Returns whatever is set up on the attribute
        """
        return self.provider

    def list_users(self):
        """
        Returns the list of users that
        we have created
        """
        return self.users.values()

    def has_bucket_access(self, bucket, username):
        """
        Check permissions on a user and a bucket
        """
        try:
            return bucket in self.users[username].permissions.keys()
        except KeyError:
            raise NotFoundError("User not found")

    def get_user(self, name):
        """
        Tries to retrieve a user from the dict
        """
        return self.users.get(name)

    def list_bucket(self, backend):
        """
        Returns the list of users
        """
        return self.buckets.values()

    def create_user(self, name):
        """
        Create and return a new user
        and add it to the dict
        """
        if not name in self.users.keys():
            new_user = User(name)
            self.users[name] = new_user
            return new_user
        else:
            raise RequestError("User already exists", 400)

    def delete_user(self, name):
        """
        Removes a user from the list
        """
        if name in self.users.keys():
            del self.users[name]
        else:
            raise NotFoundError("User doesn't exist")

    def delete_keypair(self, name, access_key):
        """
        Delete the keypair from the user
        """
        try:
            the_user = self.users[name]
            the_user.keys = [
                key for key in the_user.keys if key["access_key"] != access_key
            ]
        except KeyError as e:
            raise e

    def delete_all_keypairs(self, name):
        """
        Deletes all keypairs from a user
        """
        try:
            self.users[name].keys = []
        except KeyError:
            raise NotFoundError("The user doesn't exist")

    def create_keypair(self, name):
        """
        Create a fake keypair for a user
        """
        try:
            the_user = self.users[name]
            access_key = "".join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(8)
            )
            secret_key = "".join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(16)
            )
            new_key = {"access_key": access_key, "secret_key": secret_key}
            the_user.keys.append(new_key)
            return new_key
        except KeyError as e:
            raise e

    def get_bucket(self, name):
        """
        Retrieve a bucket from the list
        """
        try:
            return self.buckets[name]
        except KeyError:
            raise NotFoundError("Bucket not found")

    def get_or_create_user(self, name):
        """
        Try to get a user and if it fails
        creates a new one
        """
        return self.get_user(name) or self.create_user(name)

    def get_or_create_bucket(self, name):
        """
        Tries to get a bucket and if it fails
        creates a new one
        """
        try:
            return self.get_bucket(name)
        except NotFoundError:
            mock_key = "XXXXXXXXXX"
            mock_secret = "YYYYYYYYYYYYYYYYYY"
            return self.create_bucket(name, mock_key, mock_secret)

    def create_bucket(self, name, access_key=None, secret_key=None):
        """
        Create a user and insert it in our dictionary
        """
        if not name in self.buckets.keys():
            self.bucket_counter += 1
            bucket = Bucket(name, self.bucket_counter, 1024)
            self.buckets[name] = bucket
        else:
            raise RequestError("Bucket name already exists", 400)

    def edit_bucket_template(self, template_id, **kwargs):
        """
        Modifies the template
        """
        if template_id == 1:
            return None
        else:
            raise NotFoundError("Template not found")

    def update_bucket_acl(self, bucket, new_grant):
        """
        Updates the bucket ACL
        """
        if bucket in self.buckets.keys():
            return None
        else:
            raise RequestError("Bucket not found", 400)

    def set_bucket_quota(self, bucket, quota_unit, quota):
        try:
            self.buckets[bucket].quota = quota
        except KeyError:
            raise RequestError("Bucket not found", 400)

    def add_bucket_acl(self, bucket, user, access=None):
        if not bucket in self.buckets.keys():
            raise NotFoundError("Bucket not found")
        elif not user in self.users.keys():
            raise NotFoundError("Bucket not found")
        else:
            self.users[user].permissions[bucket] = access

    def delete_bucket_acl(self, bucket, user):
        """
        Remove user's permission from a bucket
        Args:
            bucket (str): bucket name
            user (str): user name
        Returns:
            None
        """
        if not bucket in self.buckets.keys():
            raise NotFoundError("Bucket not found")
        elif not user in self.users.keys():
            raise NotFoundError("Bucket not found")
        else:
            self.users[user].permissions[bucket] = []

    def delete_bucket(self, bucket_name):
        try:
            del self.buckets[bucket_name]
            return None
        except:
            return None
