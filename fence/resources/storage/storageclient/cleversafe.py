"""
Connection manager for the Cleversafe storage system
Since it is compatible with S3, we will be using boto.
"""

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
import requests
from urllib.parse import urlencode
import json
from .base import StorageClient, User, Bucket, handle_request
from .errors import RequestError, NotFoundError

from fence.config import config


class CleversafeClient(StorageClient):
    """
    Connection manager for Cleversafe.
    Isolates differences from other connectors
    """

    def __init__(self, config):
        """
        Creation of the manager. Since it is only s3 compatible
        we need to specify the endpoint in the config
        """
        super(CleversafeClient, self).__init__(__name__)
        self._config = config
        self._host = config["host"]
        self._public_host = config["public_host"]
        self._access_key = config["aws_access_key_id"]
        self._secret_key = config["aws_secret_access_key"]
        self._username = config["username"]
        self._password = config["password"]
        self._permissions_order = {
            "read-storage": 1,
            "write-storage": 2,
            "admin-storage": 3,
            "disabled": 0,
        }
        self._permissions_value = ["disabled", "readOnly", "readWrite", "owner"]
        self._auth = requests.auth.HTTPBasicAuth(self._username, self._password)
        self._bucket_name_id_table = {}
        self._update_bucket_name_id_table()
        self._user_name_id_table = {}
        self._user_id_name_table = {}
        self._update_user_name_id_table()

    def _update_user_name_id_table(self):
        """
        Update the name-id translation table for users
        """
        response = self._request("GET", "listAccounts.adm")
        if response.status_code == 200:
            jsn = json.loads(response.text)
            self._user_name_id_table = {}
            for user in jsn["responseData"]["accounts"]:
                self._user_name_id_table[user["name"]] = user["id"]
                self._user_id_name_table[user["id"]] = user["name"]
            self.logger.debug(self._user_name_id_table)
            self.logger.debug(self._user_id_name_table)
        else:
            msg = "List users failed on update cache with code {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def _update_bucket_name_id_table(self):
        """
        Update the name-id translation table for buckets
        """
        response = self._request("GET", "listVaults.adm")
        if response.status_code == 200:
            jsn = json.loads(response.text)
            self._bucket_name_id_table = {}
            for user in jsn["responseData"]["vaults"]:
                self._bucket_name_id_table[user["name"]] = user["id"]
            self.logger.debug(self._bucket_name_id_table)
        else:
            msg = "List vaults failed on update cache with code {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def _get_bucket_id(self, name):
        """
        Tries to return the id from the table
        If the cache misses, it updates it and
        tries again
        TODO OPTIMIZATION get the user information
        from the update itself
        """
        try:
            return self._bucket_name_id_table[name]
        except KeyError:
            self._update_bucket_name_id_table()
            return self._bucket_name_id_table[name]

    def _get_user_id(self, name):
        """
        Tries to return the id from the table
        If the cache misses, it updates it and
        tries again
        """
        try:
            return self._user_name_id_table[name]
        except KeyError:
            self._update_user_name_id_table()
            return self._user_name_id_table[name]

    def _get_user_by_id(self, uid):
        """
        Fetches the user by id from the REST API
        """
        response = self._request("GET", "viewSystem.adm", itemType="account", id=uid)
        if response.status_code == 200:
            user = json.loads(response.text)
            try:
                return self._populate_user(user["responseData"]["accounts"][0])
            except:
                # Request OK but User not found
                return None
        else:
            self.logger.error(
                "get_user failed with code: {code}".format(code=response.status_code)
            )
            raise RequestError(response.text, response.status_code)

    def _populate_user(self, data):
        """
        Populates a new user with the data provided
        in a jsonreponse
        """
        try:
            new_user = User(data["name"])
            new_user.id = data["id"]
            for key in data["accessKeys"]:
                new_key = {
                    "access_key": key["accessKeyId"],
                    "secret_key": key["secretAccessKey"],
                }
                new_user.keys.append(new_key)
            vault_roles = []
            for role in data["roles"]:
                if role["role"] == "vaultUser":
                    vault_roles = role["vaultPermissions"]
            for vault_permission in vault_roles:
                vault_response = self._get_bucket_by_id(vault_permission["vault"])
                vault = json.loads(vault_response.text)
                new_user.permissions[vault["responseData"]["vaults"][0]["name"]] = (
                    vault_permission["permission"]
                )
            return new_user
        except KeyError as key_e:
            msg = "Failed to parse the user data. Check user fields inside the accounts section"
            self.logger.error(msg)
            raise RequestError(str(key_e), "200")

    def _get_bucket_by_id(self, vid):
        """
        Get bucket by id
        """
        response = self._request("GET", "viewSystem.adm", itemType="vault", id=vid)
        if response.status_code == 200:
            return response
        else:
            msg = "Get bucket by id failed with code: {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    @handle_request
    def _request(self, method, operation, payload=None, **kwargs):
        """
        Compose the request and send it
        """
        base_url = "https://{host}/manager/api/json/1.0/{oper}".format(
            host=self._host, oper=operation
        )
        url = base_url + "?" + urlencode(dict(**kwargs))
        return requests.request(
            method,
            url,
            auth=self._auth,
            data=payload,
            verify=config["VERIFY_CLEVERSAFE_CERT"],
        )  # self-signed certificate

    @property
    def provider(self):
        """
        Returns the type of storage
        """
        return "Cleversafe"

    def list_users(self):
        """
        Returns a list with all the users, in User objects
        """
        response = self._request("GET", "listAccounts.adm")
        if response.status_code == 200:
            jsn = json.loads(response.text)
            user_list = []
            for user in jsn["responseData"]["accounts"]:
                new_user = self._populate_user(user)
                user_list.append(new_user)
            return user_list
        else:
            msg = "List buckets failed with code {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def has_bucket_access(self, bucket, username):
        """
        Find if a user is in the grants list of the acl for
        a certain bucket.
        Please keep in mind that buckets must be all lowercase
        """
        vault_id = self._get_bucket_id(bucket)
        vault = json.loads(self._get_bucket_by_id(vault_id).text)
        user_id = self._get_user_id(username)
        for permission in vault["responseData"]["vaults"][0]["accessPermissions"]:
            if permission["principal"]["id"] == user_id:
                return True
        return False

    def get_user(self, name):
        """
        Gets the information from the user including
        but not limited to:
        - username
        - name
        - roles
        - permissions
        - access_keys
        - emailxs
        """
        try:
            uid = self._get_user_id(name)
        except KeyError:
            return None
        return self._get_user_by_id(uid)

    def list_buckets(self):
        """
        Lists all the vaults(buckets) and their information
        """
        response = self._request("GET", "listVaults.adm")
        if response.status_code == 200:
            buckets = json.loads(response.text)
            bucket_list = []
            for buck in buckets["responseData"]["vaults"]:
                new_bucket = Bucket(buck["name"], buck["id"], buck["hardQuota"])
                bucket_list.append(new_bucket)
            return bucket_list
        else:
            self.logger.error(
                "List buckets failed with code: {code}".format(
                    code=response.status_code
                )
            )
            raise RequestError(response.text, response.status_code)

    def create_user(self, name):
        """
        Creates a user
        TODO Input sanitazion for parameters
        """
        data = {"name": name, "usingPassword": "false"}
        response = self._request("POST", "createAccount.adm", payload=data)
        if response.status_code == 200:
            parsed_reply = json.loads(response.text)
            user_id = parsed_reply["responseData"]["id"]
            self._update_user_name_id_table()
            return self._get_user_by_id(user_id)
        else:
            self.logger.error(
                "User creation failed with code: {0}".format(response.status_code)
            )
            raise RequestError(response.text, response.status_code)

    def delete_user(self, name):
        """
        Eliminate a user account
        Requires the password from the account requesting the deletion
        """
        uid = self._get_user_id(name)
        data = {"id": uid, "password": self._config["password"]}
        response = self._request("POST", "deleteAccount.adm", payload=data)
        if response.status_code == 200:
            self._update_user_name_id_table()
            return None
        else:
            self.logger.error(
                "Delete user failed with code: {0}".format(response.status_code)
            )
            raise RequestError(response.text, response.status_code)

    def delete_keypair(self, name, access_key):
        """
        Remove the give key/secret that match the key id
        """
        uid = self._get_user_id(name)
        data = {"id": uid, "accessKeyId": access_key, "action": "remove"}
        response = self._request("POST", "editAccountAccessKey.adm", payload=data)
        if response.status_code == 200:
            return None
        else:
            self.logger.error(
                "Delete keypair failed with code: {0}".format(response.status_code)
            )
            raise RequestError(response.text, response.status_code)

    def delete_all_keypairs(self, name):
        """
        Remove all keys from a give user
        TODO Make this robust against possible errors so most of the keys are deleted
        or retried
        """
        user = self.get_user(name)
        exception = False
        responses_list = []
        responses_codes = []
        for key in user.keys:
            try:
                self.delete_keypair(user.username, key["access_key"])
            except RequestError as exce:
                exception = True
                msg = "Remove all keys failed for one key"
                self.logger.error(msg.format(exce.code))
                responses_list.append(str(exce))
                responses_codes.append(exce.code)
        if exception:
            raise RequestError(responses_list, responses_codes)
        else:
            return None

    def create_keypair(self, name):
        """
        Add a new key/secret pair
        """
        uid = self._get_user_id(name)
        data = {"id": uid, "action": "add"}
        response = self._request("POST", "editAccountAccessKey.adm", payload=data)
        if response.status_code == 200:
            jsn = json.loads(response.text)
            keypair = {
                "access_key": jsn["responseData"]["accessKeyId"],
                "secret_key": jsn["responseData"]["secretAccessKey"],
            }
            return keypair
        else:
            msg = "Create keypair failed with error code: {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def get_bucket(self, bucket):
        """
        Retrieves the information from the bucket matching the name
        """
        try:
            bucket_id = self._get_bucket_id(bucket)
            """at this point we have all we need for the initial
            Bucket object, but for coherence, we keep this last call.
            Feel free to get more information from response.text"""
            response = self._get_bucket_by_id(bucket_id)
            vault = json.loads(response.text)
            return Bucket(
                bucket, bucket_id, vault["responseData"]["vaults"][0]["hardQuota"]
            )
        except KeyError as exce:
            self.logger.error("Get bucket not found on cache")
            raise RequestError(str(exce), "NA")
        except RequestError as exce:
            self.logger.error("Get bucket failed retrieving bucket info")
            raise exce

    def get_or_create_user(self, name):
        """
        Tries to get a user and if it doesn't exist, creates a new one
        """
        user = self.get_user(name)
        if user != None:
            return user
        else:
            return self.create_user(name)

    def get_or_create_bucket(self, bucket_name, access_key=None, secret_key=None):
        """
        Tries to retrieve a bucket and if it doesn't exist, creates a new one
        """
        bucket = self.get_bucket(bucket_name)
        if bucket != None:
            return bucket
        else:
            if not access_key:
                access_key = self._access_key
            if not secret_key:
                secret_key = self._secret_key
            return self.create_bucket(bucket_name, access_key, secret_key)

    def create_bucket(self, bucket_name, access_key=None, secret_key=None):
        """
        Requires a default template created on cleversafe
        """
        if not access_key:
            access_key = self._access_key
        if not secret_key:
            secret_key = self._secret_key
        host = self._public_host
        creds = {"endpoint_url": f"https://{host}"}
        creds["aws_access_key_id"] = access_key
        creds["aws_secret_access_key"] = secret_key
        s3_client = boto3.client(
            "s3",
            config=Config(s3={"addressing_style": "path"})  # Enforces path style,
            ** creds,
        )
        try:
            bucket = s3_client.create_bucket(Bucket=bucket_name)
            self._update_bucket_name_id_table()
            return bucket
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            self.logger.error(f"Create bucket failed with error code: {error_code}")
            raise RequestError(str(e), error_code)

    def edit_bucket_template(self, default_template_id, **kwargs):
        """
        Change the desired parameters of the default template
        This will affect every new bucket creation
        The idea is to have only one template, the default one, and
        modify it accordingly
        """
        data = kwargs
        data["id"] = default_template_id
        response = self._request("POST", "editVaultTemplate.adm", payload=data)
        if response.status_code == 200:
            return response
        else:
            msg = "Edit bucket template failed with code: {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def update_bucket_acl(self, bucket, new_grants):
        """
        Get an acl object and add the missing credentials
        to the one retrieved from the target bucket
        new_grants contains a list of users and permissions
        [('user1', ['read-storage', 'write-storage']),...]
        """
        user_id_list = []
        for user in new_grants:
            user_id_list.append(self._get_user_id(user[0]))
        bucket_id = self._get_bucket_id(bucket)
        response = self._get_bucket_by_id(bucket_id)
        vault = json.loads(response.text)["responseData"]["vaults"][0]
        disable = []
        for permission in vault["accessPermissions"]:
            uid = permission["principal"]["id"]
            permit_type = permission["permission"]
            if uid not in user_id_list or permit_type != "owner":
                disable.append((self._user_id_name_table[uid], ["disabled"]))
        for user in disable:
            self.add_bucket_acl(bucket, user[0], user[1])
        for user in new_grants:
            self.add_bucket_acl(bucket, user[0], user[1])

    def set_bucket_quota(self, bucket, quota_unit, quota):
        """
        Set qouta for the entire bucket/vault
        """
        bid = self._get_bucket_id(bucket)
        data = {"hardQuotaSize": quota, "hardQuotaUnit": quota_unit, "id": bid}
        response = self._request("POST", "editVault.adm", payload=data)
        if response.status_code == 200:
            return response
        else:
            msg = "Set bucket quota failed with code: {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def add_bucket_acl(self, bucket, username, access=[]):
        """
        Add permissions to a user on the bucket ACL
        """
        try:
            bucket_param = "vaultUserPermissions[{0}]".format(
                self._get_bucket_id(bucket)
            )
        except KeyError:
            msg = "Bucket {0} wasn't found on the database"
            self.logger.error(msg.format(bucket))
            raise NotFoundError(msg.format(bucket))
        try:
            access_lvl = max(self._permissions_order[role] for role in access)
            data = {
                "id": self._get_user_id(username),
                bucket_param: self._permissions_value[access_lvl],
            }
            if access_lvl == 3:
                data["rolesMap[vaultProvisioner]"] = "true"
        except KeyError:
            msg = "User {0} wasn't found on the database"
            self.logger.error(msg.format(username))
            raise NotFoundError(msg.format(username))
        response = self._request("POST", "editAccount.adm", payload=data)
        if response.status_code != 200:
            msg = "Error trying to change buket permissions for user {0}"
            self.logger.error(msg.format(username))
            raise RequestError(msg.format(username), response.status_code)

    def delete_bucket(self, bucket_name):
        """
        Delete a bucket
        """
        bucket_id = self._get_bucket_id(bucket_name)
        data = {"id": bucket_id, "password": self._password}
        response = self._request("POST", "deleteVault.adm", payload=data)
        self._update_bucket_name_id_table()
        if response.status_code != 200:
            msg = "Error trying to delete vault {bucket}"
            self.logger.error(msg.format(bucket_name))
            raise RequestError(msg.format(bucket_name), response.status_code)

    def delete_bucket_acl(self, bucket, username):
        """
        Remove permission from a bucket
        """
        self.add_bucket_acl(bucket, username, ["disabled"])
        return None
