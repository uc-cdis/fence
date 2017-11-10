from ...errors import Unauthorized
from ...models import CloudProvider, Bucket
from functools import wraps
from ...errors import NotSupported


def check_exist(f):
    @wraps(f)
    def wrapper(self, backend, *args, **kwargs):
        if backend not in self.clients:
            raise NotSupported("This backend is not supported by the system!")
        return f(self, backend, *args, **kwargs)

    return wrapper


privileges = [
    "read-storage",
    "write-storage",
    "admin"
]


class StorageManager(object):
    def __init__(self, credentials):
        self.clients = {}
        for backend, config in credentials.iteritems():
            self.clients[backend] = get_client(config=config, backend=backend)

    def check_auth(self, backend, user):
        """
        check if the user should be authorized to storage resources
        """
        storage_access = any(
           ['read-storage' in item for item
             in user.project_access.values()])
        backend_access = any([
           sa.provider.backend == backend for p in user.projects.values()
           for sa in p.storage_access
        ])
        if storage_access and backend_access:
            return True
        else:
            raise Unauthorized("Your are not authorized")

    @check_exist
    def create_keypair(self, backend, user):
        """
        create keypair
        :returns: None
        """
        self.check_auth(backend, user)
        self.clients[backend].get_or_create_user(user.username)
        keypair = self.clients[backend].create_keypair(user.username)
        return keypair

    @check_exist
    def delete_keypair(self, backend, user, access_key):
        """
        delete keypair
        :returns: None
        """
        self.check_auth(backend, user)
        self.clients[backend].delete_keypair(user.username, access_key)

    @check_exist
    def list_keypairs(self, backend, user):
        """
        list user keypairs to access a storage backend
        :returns: a list of keypair dict
            [
                {
                    "access_key": "abc",
                    "secret_key": "def"
                }
            ]
        """
        self.check_auth(backend, user)
        user_info = self.clients[backend].get_or_create_user(user.username)
        return user_info.keys

    @check_exist
    def create_bucket(self, backend, session, bucketname, project):
        """
        this should be exposed via admin endpoint
        create a bucket owned by a project and store in the database
        :param project: Project object
        :param backend: storage backend, eg: cleversafe, ceph, aws-s3
        :param session: sqlalchemy session
        :param bucketname: name of the bucket
        """
        provider = session.query(CloudProvider).filter(
            CloudProvider.name == backend).one()
        bucket = session.query(Bucket).filter(
            Bucket.name == bucketname).first()
        if not bucket:
            bucket = Bucket(name=bucketname, provider=provider)

        self.clients[backend].create_bucket(bucket)

    @check_exist
    def grant_access(self, backend, user, session, project, access):
        """
        this should be exposed via admin endpoint
        grant user access to a project in storage backend
        :param access: acceess type, 'read' or 'write'
        :param project: Project object
        :param user: User object
        :param backend: storage backend
        :param session: sqlalchemy session
        """
        access = [acc for acc in access if acc in privileges]
        self.clients[backend].get_or_create_user(user.username)
        buckets = project.buckets.all()
        for b in buckets:
            self.clients[backend].add_bucket_acl(
                b.name, user.username, access=access)

    @check_exist
    def has_bucket_access(self, backend, user, bucket):
        """
        Check if the user has access to that bucket in
        particular
        :return boolean
        """
        return self.clients[backend].has_bucket_access(bucket, user.username)
        
    @check_exist
    def get_or_create_user(self, backend, user):
        """
        Gets a User object with information
        from the specific user
        :return User
        """
        return self.clients[backend].get_or_create_user(user.username)

    @check_exist
    def list_bucket(self, backend):
        """
        Get a list of bucket names
        :return ['bucket1', 'bucket2'...]
        """
        return self.clients[backend].list_buckets()

    @check_exist
    def create_user(self, backend, user):
        """
        Returns a User object
        with information from the newly
        created user
        :return User
        """
        return self.clients[backend].create_user(user.username)

    @check_exist
    def delete_user(self, backend, user):
        """
        Deletes the user
        :return None
        """
        self.clients[backend].delete_user(user.username)

    @check_exist
    def delete_all_keypairs(self, backend, user):
        """
        Remove all keypairs for the given user
        :returns None
        """
        self.clients[backend].delete_all_keypairs(user.username)

    @check_exist
    def get_or_create_bucket(self, backend, bucket):
        """
        Get a Bucket object with the
        information of the bucket
        :returns Bucket
        """
        return self.clients[backend].get_or_create_bucket(bucket)

    @check_exist
    def edit_bucket_template(self, backend, template_id, **kwargs):
        """
        Edit the template used to create buckets
        :kwargs should have the backend dependent arguments to modify
        """
        self.clients[backend].edit_bucket_template(template_id, **kwargs)

    @check_exist
    def update_bucket_acl(self, backend, bucket, new_grants):
        """
        Replace an existing ACL with a new one
        We keep owners of the bucket intact
        Please check individual storage systems for how to
        user permissions appropriately
        :new_grants pairs of users and access permissions
        [('user1', ['read-storage','write-storage'])]
        :returns None
        """
        self.clients[backend].update_bucket_acl(bucket, new_grants)

    @check_exist
    def set_bucket_quota(self, backend, bucket, quota_unit, quota):
        """
        Select the quota for the entire bucket
        Please check the different storage systems on
        how to use quotas appropriately
        :quota_unit can be Tb, Gb, Mb...
        :quota is the ammount of the previously set unit
        :returns None
        """
        self.clients[backend].set_bucket_quota(bucket, quota_unit, quota)

    @check_exist
    def add_bucket_acl(self, backend, buckets, user, session, project, access=None):
        """
        Add a new grant for a user to a specific bucket
        Please consult the manuals for the different
        storage systems to assign permissions appropriately
        :access is a list of access types granted to the
        user
        :returns None
        """
        if access is None:
            access = []
        access = [acc for acc in access if acc in privileges]
        self.clients[backend].get_or_create_user(user.username)
        buckets = project.buckets.all()
        for b in buckets:
            self.clients[backend].add_bucket_acl(
                b.name, user.username, access=access)
