import os
import os.path
import time
import yaml

from cirrus import GoogleCloudManager
from cdispyutils.log import get_logger
from userdatamodel.driver import SQLAlchemyDriver
from userdatamodel.models import (
    AccessPrivilege,
    Bucket,
    CloudProvider,
    GoogleProxyGroup,
    Group,
    IdentityProvider,
    Project,
    StorageAccess,
    User,
)

from fence.jwt.token import (
    generate_signed_access_token,
    generate_signed_refresh_token,
)
from fence.models import Client
from fence.models import GoogleServiceAccount
from fence.models import UserGoogleAccount
from fence.models import UserGoogleAccountToProxyGroup
from fence.models import UserRefreshToken
from fence.sync.sync_users import UserSyncer
from fence.utils import create_client, drop_client

logger = get_logger(__name__)


def create_client_action(
        DB, username=None, client=None, urls=None, auto_approve=True):
    try:
        print(create_client(
            username, urls, DB, name=client, auto_approve=auto_approve))
    except Exception as e:
        print(e.message)


def delete_client_action(DB, client):
    try:
        drop_client(client, DB)
        print('Client {} deleted'.format(client))
    except Exception as e:
        print(e.message)


def sync_users(dbGaP, STORAGE_CREDENTIALS, DB,
               projects=None, is_sync_from_dbgap_server=False,
               sync_from_local_csv_dir=None, sync_from_local_yaml_file=None):
    '''
    sync ACL files from dbGap to auth db and storage backends
    imports from local_settings is done here because dbGap is
    an optional requirment for fence so it might not be specified
    in local_settings
    Args:
        projects: path to project_mapping yaml file which contains mapping
        from dbgap phsids to projects in fence database
    Returns:
        None
    Examples:
        the expected yaml structure sould look like:
        .. code-block:: yaml
            phs000178:
              - name: TCGA
                auth_id: phs000178
              - name: TCGA-PCAWG
                auth_id: TCGA-PCAWG
            phs000235:
              - name: CGCI
                auth_id: phs000235
    '''

    if ((is_sync_from_dbgap_server or sync_from_local_csv_dir) and projects is None):
        logger.error("=====project mapping needs to be provided!!!=======")
        return
    if ((is_sync_from_dbgap_server or sync_from_local_csv_dir) and not os.path.exists(projects)):
        logger.error("====={} is not found!!!=======".format(projects))
        return
    if sync_from_local_csv_dir and not os.path.exists(sync_from_local_csv_dir):
        logger.error("====={} is not found!!!=======".format(
            sync_from_local_csv_dir))
        return
    if sync_from_local_yaml_file and not os.path.exists(sync_from_local_yaml_file):
        logger.error("====={} is not found!!!=======".format(
            sync_from_local_yaml_file))
        return

    project_mapping = None
    if projects:
        try:
            with open(projects, 'r') as f:
                project_mapping = yaml.load(f)
        except IOError:
            pass

    syncer = UserSyncer(
        dbGaP, DB, project_mapping=project_mapping,
        storage_credentials=STORAGE_CREDENTIALS,
        is_sync_from_dbgap_server=is_sync_from_dbgap_server,
        sync_from_local_csv_dir=sync_from_local_csv_dir,
        sync_from_local_yaml_file=sync_from_local_yaml_file
    )
    syncer.sync()


def create_sample_data(DB, yaml_input):
    with open(yaml_input, 'r') as f:
        data = yaml.load(f)

    db = SQLAlchemyDriver(DB)
    with db.session as s:
        create_cloud_providers(s, data)
        create_projects(s, data)
        create_group(s, data)
        create_users_with_group(DB, s, data)


def create_group(s, data):
    for group_name, fields in data['groups'].iteritems():
        projects = fields.get('projects', [])
        group = s.query(Group).filter(Group.name == group_name).first()
        if not group:
            group = Group(name=group_name)
        for project_data in projects:
            grant_project_to_group_or_user(s, project_data, group)


def create_projects(s, data):
    projects = data.get('projects', [])
    for project in projects:
        create_project(s, project)


def create_project(s, project_data):
    auth_id = project_data['auth_id']
    name = project_data.get('name', auth_id)
    project = s.query(Project).filter_by(name=name).first()
    if project is None:
        project = Project(name=name, auth_id=auth_id)
        s.add(project)
    if 'storage_accesses' in project_data:
        sa_list = project_data['storage_accesses']
        for storage_access in sa_list:
            provider = storage_access['name']
            buckets = storage_access.get('buckets', [])
            sa = (
                s.query(StorageAccess)
                .join(StorageAccess.provider, StorageAccess.project)
                .filter(Project.name == project.name)
                .filter(CloudProvider.name == provider).first()
            )
            if not sa:
                c_provider = (
                    s
                    .query(CloudProvider)
                    .filter_by(name=provider)
                    .first()
                )
                sa = StorageAccess(provider=c_provider, project=project)
                s.add(sa)
                print(
                    'created storage access for {} to {}'
                    .format(project.name, c_provider.name)
                )
            for bucket in buckets:
                b = (
                    s.query(Bucket)
                    .filter_by(name=bucket)
                    .join(Bucket.provider)
                    .filter(CloudProvider.name == provider)
                    .first()
                )
                print(b)
                if not b:
                    b = Bucket(name=bucket)
                    b.provider = c_provider
                    s.add(b)
                    print('created bucket {} in db'.format(bucket))

    return project


def grant_project_to_group_or_user(s, project_data, group=None, user=None):
    privilege = project_data['privilege']
    project = create_project(s, project_data)
    if group:
        ap = (
            s
            .query(AccessPrivilege).
            join(AccessPrivilege.project)
            .join(AccessPrivilege.research_group)
            .filter(Project.name == project.name, Group.name == group.name)
            .first()
        )
        name = group.name
    elif user:
        ap = (
            s
            .query(AccessPrivilege)
            .join(AccessPrivilege.project)
            .join(AccessPrivilege.user)
            .filter(
                Project.name == project.name,
                User.username == user.username,
            )
            .first()
        )
        name = user.username
    else:
        raise Exception('need to provide either a user or group')
    if not ap:
        if group:
            ap = AccessPrivilege(
                project=project, research_group=group, privilege=privilege
            )
        elif user:
            ap = AccessPrivilege(
                project=project, user=user, privilege=privilege
            )
        else:
            raise Exception('need to provide either a user or group')
        s.add(ap)
        print(
            'created access privilege {} of project {} to {}'
            .format(privilege, project.name, name)
        )
    else:
        ap.privilege = privilege
        print('updated access privilege {} of project {} to {}'
              .format(privilege, project.name, name))


def create_cloud_providers(s, data):
    cloud_data = data.get('cloud_providers', [])
    for name, fields, in cloud_data.iteritems():
        cloud_provider = s.query(CloudProvider).filter(
            CloudProvider.name == name
        ).first()
        if not cloud_provider:
            cloud_provider = CloudProvider(
                name=name, backend=fields.get('backend', 'cleversafe'),
                service=fields.get('service', 'storage')
            )
            s.add(cloud_provider)


def create_users_with_group(DB, s, data):
    providers = {}
    data_groups = data['groups']
    for username, data in data['users'].iteritems():
        is_existing_user = True
        user = s.query(User).filter(User.username == username).first()
        admin = data.get('admin', False)

        if not user:
            is_existing_user = False
            provider_name = data.get('provider', 'google')
            provider = providers.get(provider_name)
            if not provider:
                provider = s.query(IdentityProvider).filter(
                    IdentityProvider.name == provider_name).first()
                providers[provider_name] = provider
                if not provider:
                    raise Exception(
                        'provider {} not found'.format(provider_name))

            user = User(
                username=username, idp_id=provider.id, is_admin=admin
            )
        user.is_admin = admin
        group_names = data.get('groups', [])
        for group_name in group_names:
            assign_group_to_user(s, user, group_name, data_groups[group_name])
        projects = data.get('projects', [])
        for project in projects:
            grant_project_to_group_or_user(s, project, user=user)
        if not is_existing_user:
            s.add(user)
        for client in data.get('clients', []):
            create_client_action(DB, username=username, **client)


def assign_group_to_user(s, user, group_name, group_data):
    group = s.query(Group).filter(Group.name == group_name).first()
    if not group:
        group = Group(name=group_name)
        s.add(group)
        user.groups.append(group)
    if group not in user.groups:
        user.groups.append(group)


def google_init(db):
    # Initial user proxy group creation
    db = SQLAlchemyDriver(db)
    with db.session as s:
        users_without_proxy = (
            s.query(User).filter(User.google_proxy_group == None)
        )

        for user in users_without_proxy:
            with GoogleCloudManager() as g_mgr:
                response = g_mgr.create_proxy_group_for_user(
                    user.id, user.username)

                group = response["group"]
                primary_service_account = response["primary_service_account"]
                user.google_proxy_group_id = group["id"]

                # Add user's primary service account to database
                service_account = GoogleServiceAccount(
                    google_unique_id=primary_service_account["uniqueId"],
                    client_id=None,
                    user_id=user.id,
                    email=primary_service_account["email"],
                    google_project_id=primary_service_account['projectId']
                )

                proxy_group = GoogleProxyGroup(
                    id=group["id"],
                    email=group["email"]
                )

                s.add(service_account)
                s.add(proxy_group)
                s.commit()


def remove_expired_google_service_account_keys(db):
    db = SQLAlchemyDriver(db)
    with db.session as s:
        client_service_accounts = (
            s.query(GoogleServiceAccount, Client).filter(
                GoogleServiceAccount.client_id == Client.client_id)
        )

        with GoogleCloudManager() as g_mgr:
            for service_account, client in client_service_accounts:
                g_mgr.handle_expired_service_account_keys(
                    service_account.google_unique_id)


def remove_expired_google_accounts_from_proxy_groups(db):
    db = SQLAlchemyDriver(db)
    with db.session as current_session:
        current_time = int(time.time())
        print('Current time: {}'.format(current_time))

        expired_accounts = (
            current_session.query(UserGoogleAccountToProxyGroup)
            .filter(
                UserGoogleAccountToProxyGroup
                .expires <= current_time)
        )

        with GoogleCloudManager() as g_mgr:
            for expired_account_access in expired_accounts:
                g_account = (
                    current_session.query(UserGoogleAccount)
                    .filter(
                        UserGoogleAccount.id ==
                        expired_account_access.user_google_account_id).first()
                )
                try:
                    response = g_mgr.remove_member_from_group(
                        member_email=g_account.email,
                        group_id=expired_account_access.proxy_group_id
                    )
                    response_error_code = response.get('error', {}).get('code')

                    if not response_error_code:
                        current_session.delete(expired_account_access)
                        print(
                            'INFO: Removed {} from proxy group with id {}.\n'
                            .format(
                                g_account.email,
                                expired_account_access.proxy_group_id)
                        )
                    else:
                        print(
                            'ERROR: Google returned an error when attempting to '
                            'remove member {} from proxy group {}. Error:\n{}\n'
                            .format(
                                g_account.email,
                                expired_account_access.proxy_group_id,
                                response)
                        )
                except Exception as exc:
                    print(
                        'ERROR: Google returned an error when attempting to '
                        'remove member {} from proxy group {}. Error:\n{}\n'
                        .format(
                            g_account.email,
                            expired_account_access.proxy_group_id,
                            exc)
                    )


def delete_users(DB, usernames):
    driver = SQLAlchemyDriver(DB)
    with driver.session as session:
        # NOTE that calling ``.delete()`` on the query itself will not follow
        # cascade deletion rules set up in any relationships.
        users_to_delete = (
            session
            .query(User)
            .filter(User.username.in_(usernames))
            .all()
        )
        for user in users_to_delete:
            session.delete(user)
        session.commit()


class JWTCreator(object):

    required_kwargs = [
        'kid',
        'private_key',
        'username',
        'scopes',
    ]
    all_kwargs = required_kwargs + [
        'expires_in',
    ]

    default_expiration = 3600

    def __init__(self, db, base_url=None, **kwargs):
        self.db = db
        self.base_url = base_url

        # These get assigned values just below here, with setattr. Defined here
        # so linters won't complain they're undefined.
        self.kid = None
        self.private_key = None
        self.username = None
        self.scopes = None

        for required_kwarg in self.required_kwargs:
            if required_kwarg not in kwargs:
                raise ValueError(
                    'missing required argument: ' + required_kwarg
                )

        # Set attributes on this object from the kwargs.
        for kwarg_name in self.all_kwargs:
            setattr(self, kwarg_name, kwargs[kwarg_name])

        # If the scopes look like this:
        #
        #     'openid,fence,data'
        #
        # convert them to this:
        #
        #     ['openid', 'fence', 'data']
        if isinstance(getattr(self, 'scopes', ''), str):
            self.scopes = [scope.strip() for scope in self.scopes.split(',')]

        self.expires_in = kwargs.get('expires_in') or self.default_expiration

    def create_access_token(self):
        """
        Create a new access token.

        Return:
            JWTResult: result containing the encoded token and claims
        """
        driver = SQLAlchemyDriver(self.db)
        with driver.session as current_session:
            user = (
                current_session.query(User)
                .filter_by(username=self.username)
                .first()
            )
            if not user:
                raise EnvironmentError(
                    'no user found with given username: ' + self.username
                )
            return generate_signed_access_token(
                self.kid, self.private_key, user, self.expires_in, self.scopes
            )

    def create_refresh_token(self):
        """
        Create a new refresh token and add its entry to the database.

        Return:
            JWTResult: the refresh token result
        """
        driver = SQLAlchemyDriver(self.db)
        with driver.session as current_session:
            user = (
                current_session.query(User)
                .filter_by(username=self.username)
                .first()
            )
            if not user:
                raise EnvironmentError(
                    'no user found with given username: ' + self.username
                )
            jwt_result = generate_signed_refresh_token(
                self.kid, self.private_key, user, self.expires_in, self.scopes
            )

            current_session.add(UserRefreshToken(
                jti=jwt_result.claims['jti'], userid=user.id,
                expires=jwt_result.claims['exp']
            ))

            return jwt_result
