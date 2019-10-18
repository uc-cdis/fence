import copy
from functools import wraps

from storageclient import get_client

from fence.models import CloudProvider, Bucket, ProjectToBucket
from fence.errors import NotSupported, InternalError, Unauthorized


def check_exist(f):
    @wraps(f)
    def wrapper(self, provider, *args, **kwargs):
        if provider not in self.clients:
            raise NotSupported("This backend is not supported by the system!")
        return f(self, provider, *args, **kwargs)

    return wrapper


PRIVILEGES = [
    "read-storage",
    "write-storage",
    "admin"
]


def get_endpoints_descriptions(providers, session):
    desc = {}
    for provider in providers:
        if provider == 'cdis':
            desc['/cdis'] = 'access to Gen3 APIs'
        else:
            p = session.query(CloudProvider).filter_by(name=provider).first()
            if p is None:
                raise InternalError(
                    "{} is not supported by the system!".format(provider))
            desc['/' + provider] = p.description or ''
    return desc


class StorageManager(object):

    def __init__(self, credentials, logger):
        self.logger = logger
        self.clients = {}
        for provider, config in credentials.items():
            if 'backend' not in config:
                self.logger.error(
                    "Storage provider {} is not configured with backend"
                    .format(provider))
                raise InternalError("Something went wrong")

            backend = config['backend']
            creds = copy.deepcopy(config)
            del creds['backend']
            self.clients[provider] = get_client(config=config, backend=backend)

    def check_auth(self, provider, user):
        """
        check if the user should be authorized to storage resources
        """
        storage_access = any([
            'read-storage' in item
            for item in user.project_access.values()
        ])
        backend_access = any([
           sa.provider.name == provider for p in user.projects.values()
           for sa in p.storage_access
        ])
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
        provider = session.query(CloudProvider).filter(
            CloudProvider.name == provider).one()
        bucket = session.query(Bucket).filter(
            Bucket.name == bucketname).first()
        if not bucket:
            bucket = Bucket(name=bucketname, provider=provider)
            bucket = session.merge(bucket)
        if not session.query(ProjectToBucket).filter(
                ProjectToBucket.bucket_id == bucket.id,
                ProjectToBucket.project_id == project.id).first():
            project_to_bucket = ProjectToBucket(bucket=bucket, project=project)
            session.add(project_to_bucket)
        c = self.clients[provider.name]
        c.get_or_create_bucket(bucketname)

    @check_exist
    def grant_access(self, provider, username, project, access):
        """
        this should be exposed via admin endpoint
        grant user access to a project in storage backend
        :param access: acceess type, 'read' or 'write'
        :param project: Project object
        :param username: username
        :param provider: storage backend provider
        """
        access = [acc for acc in access if acc in PRIVILEGES]
        user = self.clients[provider].get_or_create_user(username)
        for b in project.buckets:
            self.clients[provider].add_bucket_acl(
                b.name, user.username, access=access)

    @check_exist
    def revoke_access(self, provider, username, project):
        """
        this should be exposed via admin endpoint
        revoke user access to a project in storage backend
        :param project: Project object
        :param username: username
        :param backend: storage backend provider
        """
        user = self.clients[provider].get_user(username)
        if user is None:
            return
        for b in project.buckets:
            self.clients[provider].delete_bucket_acl(
                b.name, user.username)

    @check_exist
    def has_bucket_access(self, provider, user, bucket):
        """
        Check if the user has access to that bucket in
        particular
        :return boolean
        """
        return self.clients[provider].has_bucket_access(bucket, user.username)

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

    @check_exist
    def add_bucket_acl(
            self, provider, buckets, user, session, project, access=None):
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
        access = [acc for acc in access if acc in PRIVILEGES]
        self.clients[provider].get_or_create_user(user.username)
        buckets = project.buckets.all()
        for b in buckets:
            self.clients[provider].add_bucket_acl(
                b.name, user.username, access=access)

    def delete_bucket(self, backend, bucket_name):
        """
        Remove a bucket from the speficied bucket
        """
        self.clients[backend].delete_bucket(bucket_name)
