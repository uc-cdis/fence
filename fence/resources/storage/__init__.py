import copy
from functools import wraps

from storageclient import get_client

from fence.models import (
    CloudProvider,
    Bucket,
    ProjectToBucket,
    GoogleBucketAccessGroup,
    User,
    GoogleProxyGroupToGoogleBucketAccessGroup,
    query_for_user,
)
from fence.errors import NotSupported, InternalError, Unauthorized, NotFound
from fence.resources.google import STORAGE_ACCESS_PROVIDER_NAME as GOOGLE_PROVIDER


def check_exist(f):
    @wraps(f)
    def wrapper(self, provider, *args, **kwargs):
        if provider not in self.clients:
            raise NotSupported("This backend is not supported by the system!")
        return f(self, provider, *args, **kwargs)

    return wrapper


# NOTE: new storage privileges are expected to have -storage as a suffix
#       ex: delete-storage
PRIVILEGES = ["read-storage", "write-storage", "admin"]


def get_endpoints_descriptions(providers, session):
    desc = {}
    for provider in providers:
        if provider == "cdis":
            desc["/cdis"] = "access to Gen3 APIs"
        else:
            p = session.query(CloudProvider).filter_by(name=provider).first()
            if p is None:
                raise InternalError(
                    "{} is not supported by the system!".format(provider)
                )
            desc["/" + provider] = p.description or ""
    return desc


class StorageManager(object):
    def __init__(self, credentials, logger):
        self.logger = logger
        self.clients = {}
        for provider, config in credentials.items():
            if "backend" not in config:
                self.logger.error(
                    "Storage provider {} is not configured with backend".format(
                        provider
                    )
                )
                raise InternalError("Something went wrong")

            backend = config["backend"]
            creds = copy.deepcopy(config)
            del creds["backend"]
            self.clients[provider] = get_client(config=config, backend=backend)

    def check_auth(self, provider, user):
        """
        check if the user should be authorized to storage resources
        """
        storage_access = any(
            ["read-storage" in item for item in list(user.project_access.values())]
        )
        backend_access = any(
            [
                sa.provider.name == provider
                for p in list(user.projects.values())
                for sa in p.storage_access
            ]
        )
        if storage_access and backend_access:
            return True
        else:
            raise Unauthorized("Your are not authorized")

    @check_exist
    def create_keypair(self, provider, user):
        """
        create keypair
        :returns: None
        """
        self.check_auth(provider, user)
        self.clients[provider].get_or_create_user(user.username)
        keypair = self.clients[provider].create_keypair(user.username)
        return keypair

    @check_exist
    def delete_keypair(self, provider, user, access_key):
        """
        delete keypair
        :returns: None
        """
        self.check_auth(provider, user)
        self.clients[provider].delete_keypair(user.username, access_key)

    @check_exist
    def list_keypairs(self, provider, user):
        """
        list user keypairs to access a storage provider
        :returns: a list of keypair dict
            [
                {
                    "access_key": "abc",
                    "secret_key": "def"
                }
            ]
        """
        self.check_auth(provider, user)
        user_info = self.clients[provider].get_or_create_user(user.username)
        return user_info.keys

    @check_exist
    def create_bucket(self, provider, session, bucketname, project):
        """
        this should be exposed via admin endpoint
        create a bucket owned by a project and store in the database
        :param project: Project object
        :param provider: storage provider
        :param session: sqlalchemy session
        :param bucketname: name of the bucket
        """
        provider = (
            session.query(CloudProvider).filter(CloudProvider.name == provider).one()
        )
        bucket = session.query(Bucket).filter(Bucket.name == bucketname).first()
        if not bucket:
            bucket = Bucket(name=bucketname, provider=provider)
            bucket = session.merge(bucket)
        if (
            not session.query(ProjectToBucket)
            .filter(
                ProjectToBucket.bucket_id == bucket.id,
                ProjectToBucket.project_id == project.id,
            )
            .first()
        ):
            project_to_bucket = ProjectToBucket(bucket=bucket, project=project)
            session.add(project_to_bucket)
        c = self.clients[provider.name]
        c.get_or_create_bucket(bucketname)

    @check_exist
    def grant_access(
        self, provider, username, project, access, session, google_bulk_mapping=None
    ):
        """
        this should be exposed via admin endpoint
        grant user access to a project in storage backend
        :param access: acceess type, 'read' or 'write'
        :param project: Project object
        :param username: username
        :param provider: storage backend provider
        """
        access = self._get_valid_access_privileges(access)
        storage_user = self._get_or_create_storage_user(username, provider, session)

        storage_username = StorageManager._get_storage_username(storage_user, provider)

        if storage_username:
            for b in project.buckets:
                self._update_access_to_bucket(
                    b,
                    provider,
                    storage_user,
                    storage_username,
                    access,
                    session,
                    google_bulk_mapping=google_bulk_mapping,
                )

    @check_exist
    def revoke_access(
        self, provider, username, project, session, google_bulk_mapping=None
    ):
        """
        this should be exposed via admin endpoint
        revoke user access to a project in storage backend
        :param project: Project object
        :param username: username
        :param backend: storage backend provider
        """
        storage_user = self._get_storage_user(username, provider, session)
        if storage_user is None:
            return

        storage_username = StorageManager._get_storage_username(storage_user, provider)

        if storage_username:
            for b in project.buckets:
                self._revoke_access_to_bucket(
                    b,
                    provider,
                    storage_user,
                    storage_username,
                    session,
                    google_bulk_mapping=google_bulk_mapping,
                )

    @check_exist
    def has_bucket_access(self, provider, user, bucket, access):
        """
        Check if the user has access to that bucket in
        particular
        :return boolean
        """
        access = self._get_valid_access_privileges(access)
        storage_username = StorageManager._get_storage_username(user, provider)

        return storage_username and self.clients[provider].has_bucket_access(
            bucket.name, storage_username
        )

    @check_exist
    def get_or_create_user(self, provider, user):
        """
        Gets a User object with information
        from the specific user
        :return User
        """
        return self.clients[provider].get_or_create_user(user.username)

    @check_exist
    def list_bucket(self, provider):
        """
        Get a list of bucket names
        :return ['bucket1', 'bucket2'...]
        """
        return self.clients[provider].list_buckets()

    @check_exist
    def create_user(self, provider, user):
        """
        Returns a User object
        with information from the newly
        created user
        :return User
        """
        return self.clients[provider].create_user(user.username)

    @check_exist
    def delete_user(self, provider, user):
        """
        Deletes the user
        :return None
        """
        self.clients[provider].delete_user(user.username)

    @check_exist
    def delete_all_keypairs(self, provider, user):
        """
        Remove all keypairs for the given user
        :returns None
        """
        self.clients[provider].delete_all_keypairs(user.username)

    @check_exist
    def get_or_create_bucket(self, provider, bucket):
        """
        Get a Bucket object with the
        information of the bucket
        :returns Bucket
        """
        return self.clients[provider].get_or_create_bucket(bucket)

    @check_exist
    def edit_bucket_template(self, provider, template_id, **kwargs):
        """
        Edit the template used to create buckets
        :kwargs should have the provider dependent arguments to modify
        """
        self.clients[provider].edit_bucket_template(template_id, **kwargs)

    @check_exist
    def update_bucket_acl(self, provider, bucket, new_grants):
        """
        Replace an existing ACL with a new one
        We keep owners of the bucket intact
        Please check individual storage systems for how to
        user permissions appropriately
        :new_grants pairs of users and access permissions
        [('user1', ['read-storage','write-storage'])]
        :returns None
        """
        self.clients[provider].update_bucket_acl(bucket.name, new_grants)

    @check_exist
    def set_bucket_quota(self, provider, bucket, quota_unit, quota):
        """
        Select the quota for the entire bucket
        Please check the different storage systems on
        how to use quotas appropriately
        :quota_unit can be Tb, Gb, Mb...
        :quota is the ammount of the previously set unit
        :returns None
        """
        self.clients[provider].set_bucket_quota(bucket, quota_unit, quota)

    def delete_bucket(self, backend, bucket_name):
        """
        Remove a bucket from the speficied bucket
        """
        self.clients[backend].delete_bucket(bucket_name)

    def _get_storage_user(self, username, provider, session):
        """
        Return a user.

        Depending on the provider, may call to get or just search fence's db.

        Args:
            username (str): User's name
            provider (str): backend provider
            session (userdatamodel.driver.SQLAlchemyDriver.session): fence's db
                session to query for Users

        Returns:
            fence.models.User: User with username
        """
        if provider == GOOGLE_PROVIDER:
            return query_for_user(session=session, username=username)

        return self.clients[provider].get_user(username)

    def _get_or_create_storage_user(self, username, provider, session):
        """
        Return a user.

        Depending on the provider, may call to get or create or just
        search fence's db.

        Args:
            username (str): User's name
            provider (str): backend provider
            session (userdatamodel.driver.SQLAlchemyDriver.session): fence's db
                session to query for Users

        Returns:
            fence.models.User: User with username
        """
        if provider == GOOGLE_PROVIDER:
            user = query_for_user(session=session, username=username.lower())

            if not user:
                raise NotFound(
                    "User not found with username {}. For Google Storage "
                    "Backend user's must already exist in the db and have a "
                    "Google Proxy Group.".format(username)
                )
            return user

        return self.clients[provider].get_or_create_user(username)

    def _update_access_to_bucket(
        self,
        bucket,
        provider,
        storage_user,
        storage_username,
        access,
        session,
        google_bulk_mapping=None,
    ):
        # Need different logic for google (since buckets can have multiple
        # access groups)
        if not provider == GOOGLE_PROVIDER:
            self.clients[provider].add_bucket_acl(
                bucket.name, storage_username, access=access
            )
            return

        if not bucket.google_bucket_access_groups:
            raise NotFound(
                "Google bucket {} does not have any access groups.".format(bucket.name)
            )

        access = StorageManager._get_bucket_access_privileges(access)

        for bucket_access_group in bucket.google_bucket_access_groups:
            bucket_privileges = bucket_access_group.privileges or []
            if set(bucket_privileges).issubset(access):
                bucket_name = bucket_access_group.email

                if google_bulk_mapping is not None:
                    google_bulk_mapping.setdefault(bucket_name, []).append(
                        storage_username
                    )
                    self.logger.info(
                        "User {}'s Google proxy group ({}) added to bulk mapping for Google Bucket Access Group {}.".format(
                            storage_user.email, storage_username, bucket_name
                        )
                    )
                else:
                    # NOTE: bucket_name for Google is the Google Access Group's
                    #       email address.
                    # TODO Update storageclient API for more clarity
                    self.clients[provider].add_bucket_acl(bucket_name, storage_username)

                    self.logger.info(
                        "User {}'s Google proxy group ({}) added to Google Bucket Access Group {}.".format(
                            storage_user.email, storage_username, bucket_name
                        )
                    )

                StorageManager._add_google_db_entry_for_bucket_access(
                    storage_user, bucket_access_group, session
                )

            else:
                # In the case of google, since we have multiple groups
                # with access to the bucket, we need to also remove access
                # here in case a users permissions change from read & write
                # to just read.
                StorageManager._remove_google_db_entry_for_bucket_access(
                    storage_user, bucket_access_group, session
                )

                bucket_name = bucket_access_group.email

                if google_bulk_mapping is not None:
                    google_bulk_mapping.setdefault(bucket_name, [])
                    while storage_username in google_bulk_mapping[bucket_name]:
                        google_bulk_mapping[bucket_name].remove(storage_username)
                        self.logger.debug(
                            "User {}'s Google proxy group ({}) removed from bulk mapping in Google Bucket Access Group {}.".format(
                                storage_user.email, storage_username, bucket_name
                            )
                        )

                else:
                    self.clients[provider].delete_bucket_acl(
                        bucket_name, storage_username
                    )

                    self.logger.info(
                        "User {}'s Google proxy group ({}) removed or never existed in Google Bucket Access Group {}.".format(
                            storage_user.email, storage_username, bucket_name
                        )
                    )

    def _revoke_access_to_bucket(
        self,
        bucket,
        provider,
        storage_user,
        storage_username,
        session,
        google_bulk_mapping=None,
    ):
        # Need different logic for google (since buckets can have multiple
        # access groups)
        if provider == GOOGLE_PROVIDER:
            for bucket_access_group in bucket.google_bucket_access_groups:
                StorageManager._remove_google_db_entry_for_bucket_access(
                    storage_user, bucket_access_group, session
                )
                bucket_name = bucket_access_group.email

                if google_bulk_mapping is not None:
                    google_bulk_mapping.setdefault(bucket_name, [])
                    while storage_username in google_bulk_mapping[bucket_name]:
                        google_bulk_mapping[bucket_name].remove(storage_username)
                        self.logger.debug(
                            "User {}'s Google proxy group ({}) removed from bulk mapping in Google Bucket Access Group {}.".format(
                                storage_user.email, storage_username, bucket_name
                            )
                        )
                else:
                    self.clients[provider].delete_bucket_acl(
                        bucket_name, storage_username
                    )

                    self.logger.info(
                        "User {}'s Google proxy group ({}) removed or never existed in from Google Bucket Access Group {}.".format(
                            storage_user.email, storage_username, bucket_name
                        )
                    )
        else:
            self.clients[provider].delete_bucket_acl(bucket.name, storage_username)

    @staticmethod
    def _add_google_db_entry_for_bucket_access(
        storage_user, bucket_access_group, session
    ):
        """
        Add a db entry specifying that a given user has storage access
        to the provided Google bucket access group
        """
        storage_user_access_db_entry = (
            session.query(GoogleProxyGroupToGoogleBucketAccessGroup)
            .filter_by(
                proxy_group_id=storage_user.google_proxy_group_id,
                access_group_id=bucket_access_group.id,
            )
            .first()
        )
        if not storage_user_access_db_entry:
            storage_user_access_db_entry = GoogleProxyGroupToGoogleBucketAccessGroup(
                proxy_group_id=storage_user.google_proxy_group_id,
                access_group_id=bucket_access_group.id,
            )
            session.add(storage_user_access_db_entry)
            session.commit()

    # FIXME: create a delete() on GoogleProxyGroupToGoogleBucketAccessGroup and use here.
    #        previous attempts to use similar delete() calls on other models resulting in errors
    #        with mismatched sessions during testing
    @staticmethod
    def _remove_google_db_entry_for_bucket_access(
        storage_user, bucket_access_group, session
    ):
        """
        Remove the db entry specifying that a given user has storage access
        to the provided Google bucket access group
        """
        storage_user_access_db_entry = (
            session.query(GoogleProxyGroupToGoogleBucketAccessGroup)
            .filter_by(
                proxy_group_id=storage_user.google_proxy_group_id,
                access_group_id=bucket_access_group.id,
            )
            .first()
        )
        if storage_user_access_db_entry:
            session.delete(storage_user_access_db_entry)
            session.commit()

    @staticmethod
    def _get_storage_username(user, provider):
        # Need different information for google (since buckets and
        # users are represented with Google Groups)
        username = None
        if provider == GOOGLE_PROVIDER:
            if user.google_proxy_group:
                username = user.google_proxy_group.email
        else:
            username = user.username

        return username

    @staticmethod
    def _get_valid_access_privileges(access_list):
        return [acc for acc in access_list if acc in PRIVILEGES]

    @staticmethod
    def _get_bucket_access_privileges(access_list):
        """
        Return a simplified list of bucket privileges

        ex: ['read', 'write'] instead of ['read-storage', 'write-storage']

        Args:
            access_list (List(str)): List of access levels from user info

        Returns:
            List(str): Simplified list of bucket privileges
        """
        access = StorageManager._get_valid_access_privileges(access_list)
        bucket_access = [access_level.split("-")[0] for access_level in access]
        return bucket_access
