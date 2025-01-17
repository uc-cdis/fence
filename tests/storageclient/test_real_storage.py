#!/usr/bin/env python

import json
from fence.resources.storage.storageclient import CleversafeClient, errors
import unittest


# XXX: tests to fix
import pytest

pytestmark = pytest.mark.skip


class TestStorage(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        with open("cred.json", "r") as f:
            self.creds = json.load(f)
        self.cc = CleversafeClient(self.creds)
        self.test_user = self.cc.create_user("test_suite_user")
        self.test_bucket = self.cc.create_bucket(
            self.creds["aws_access_key_id"],
            self.creds["aws_secret_access_key"],
            "test_suite_bucket",
        )

    @classmethod
    def tearDownClass(self):
        self.cc.delete_user(self.test_user.username)
        self.cc.delete_bucket(self.test_bucket.name)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_create_list_and_delete_bucket(self):
        """
        Successful creation, listing and deletion of a vault
        """
        new_bucket_name = "my_new_tested_bucket"
        self.cc.create_bucket(
            self.creds["aws_access_key_id"],
            self.creds["aws_secret_access_key"],
            new_bucket_name,
        )
        bucket = self.cc.get_bucket(new_bucket_name)
        self.assertEqual(bucket.name, new_bucket_name)
        suite_bucket_found = False
        new_bucket_found = False
        buckets = self.cc.list_buckets()
        for buck in buckets:
            if buck.name == new_bucket_name:
                new_bucket_found = True
            elif buck.name == self.test_bucket.name:
                suite_bucket_found = True
        self.assertTrue(new_bucket_found)
        self.assertTrue(suite_bucket_found)
        self.cc.delete_bucket(new_bucket_name)
        with self.assertRaises(errors.RequestError):
            self.cc.get_bucket(new_bucket_name)

    def test_create_list_and_delete_user(self):
        """
        Successful creation, listing and deletion of a user
        """
        new_user_name = "my_new_test_user"
        self.cc.create_user(new_user_name)
        user = self.cc.get_user(new_user_name)
        self.assertEqual(user.username, new_user_name)
        suite_user_found = False
        new_user_found = False
        users = self.cc.list_users()
        for user in users:
            if user.username == new_user_name:
                new_user_found = True
            elif user.username == self.test_user.username:
                suite_user_found = True
        self.assertTrue(new_user_found)
        self.assertTrue(suite_user_found)
        self.cc.delete_user(new_user_name)
        user = self.cc.get_user(new_user_name)
        self.assertEqual(user, None)

    def test_create_and_delete_keypair_success(self):
        """
        Successful creation and deletion of keys
        Check that the creation and deletion of
        keys work. We check that we keep the same
        status that we got at the start
        """
        user = self.cc.get_user(self.test_user.username)
        original_keys = user.keys
        keypair = self.cc.create_keypair(user.username)
        user = self.cc.get_user(self.test_user.username)
        self.assertIn(keypair, user.keys)
        keys = self.cc.delete_keypair(user.username, keypair["access_key"])
        user = self.cc.get_user(self.test_user.username)
        self.assertEqual(user.keys, original_keys)

    def test_delete_keypair_inexistent_key(self):
        """
        Error handling of inexistent user
        """
        with self.assertRaises(errors.RequestError):
            self.cc.delete_keypair(self.test_user.username, "inexistent_key")

    def test_set_bucket_quota_succes(self):
        """
        Successful change of quota
        """
        bucket = self.cc.get_bucket(self.test_bucket.name)
        old_quota = bucket.quota
        if old_quota != None:
            MiB = old_quota / 1048576
        else:
            MiB = 1
        self.cc.set_bucket_quota(self.test_bucket.name, "MiB", 2 * MiB)
        bucket = self.cc.get_bucket(self.test_bucket.name)
        self.assertEqual(bucket.quota / 1048576, MiB * 2)

    def test_delete_all_keypairs_success(self):
        """
        Successful deletion of all keypairs
        """
        user = self.cc.get_user(self.test_user.username)
        original_keys = user.keys
        keypair_1 = self.cc.create_keypair(user.username)
        keypair_2 = self.cc.create_keypair(user.username)
        user = self.cc.get_user(self.test_user.username)
        self.assertIn(keypair_1, user.keys)
        self.assertIn(keypair_2, user.keys)
        keys = self.cc.delete_all_keypairs(user.username)
        user = self.cc.get_user(self.test_user.username)
        self.assertEqual(user.keys, [])

    def test_edit_bucket_template_success(self):
        """
        Successful modification of a template
        This method has no way of knowing if the
        data on the template has changed,
        so once checked once that it works,
        it is here only to check that we haven't
        broken the template
        """
        self.cc.edit_bucket_template(1, description="This is a test description")
        self.cc.edit_bucket_template(1, description="")

    def test_delete_user_inexistent_user(self):
        """
        Error handling of deletion of an inexistent user
        """
        with self.assertRaises(KeyError):
            self.cc.delete_user("this_user_will_never_exist")

    def test_add_bucket_acl_user_not_found_error(self):
        """
        Error handling of adding a bucket ACL on an inexistent user
        """
        with self.assertRaises(errors.NotFoundError):
            self.cc.add_bucket_acl(
                self.test_bucket.name, "non_existent_user", ["read-storage"]
            )

    def test_add_bucket_acl_bucket_not_found_error(self):
        """
        Error handling on adding a bucket ACL on an inexistent bucket
        """
        with self.assertRaises(errors.NotFoundError):
            self.cc.add_bucket_acl(
                "non_existent_bucket", self.test_user.username, ["read-storage"]
            )

    def test_add_bucket_acl_success(self):
        """
        Successful addition of an ACL on a bucket
        This method has no way of retrieving the information
        TODO add writing test on the bucket to check permissions
        """
        self.cc.add_bucket_acl(
            self.test_bucket.name, self.test_user.username, ["read-storage"]
        )
        self.cc.add_bucket_acl(
            self.test_bucket.name, self.test_user.username, ["disabled"]
        )

    def test_get_bucket_response_error(self):
        """
        Error handling on getting an inexistent bucket
        """
        with self.assertRaises(errors.RequestError):
            self.cc.get_bucket("inexistent_bucket")

    def test_update_bucket_acl_success(self):
        """
        Successful updating of a bucket ACL
        This method has no way of retrieving the modified
        information
        TODO add a writing check
        """
        self.cc.update_bucket_acl(
            self.test_bucket.name, [(self.test_user.username, ["read-storage"])]
        )
        self.cc.update_bucket_acl(
            self.test_bucket.name, [(self.test_user.username, ["disabled"])]
        )
