# standard
import os
import os.path
import time
import uuid
import jwt
import yaml
from sqlalchemy import func


# third-party
from authlib.common.encoding import to_unicode
from cirrus import GoogleCloudManager
from cirrus.config import config as cirrus_config
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
    ProjectToBucket
)

# local
from fence.jwt.token import (
    issued_and_expiration_times,
)
from fence.models import (
    Client,
    GoogleServiceAccount,
    GoogleServiceAccountKey,
    UserGoogleAccount,
    UserGoogleAccountToProxyGroup,
    GoogleBucketAccessGroup,
    GoogleProxyGroupToGoogleBucketAccessGroup,
    UserRefreshToken
)

from fence.utils import create_client, drop_client
from fence.sync.sync_users import UserSyncer

logger = get_logger(__name__)


def create_client_action(
        DB, username=None, client=None, urls=None, auto_approve=False):
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

    if projects is not None and os.path.exists(projects) is False:
        logger.error("====={} is not found!!!=======".format(projects))
        return
    if sync_from_local_csv_dir and os.path.exists(sync_from_local_csv_dir) == False:
        logger.error("====={} is not found!!!=======".format(
            sync_from_local_csv_dir))
        return
    if sync_from_local_yaml_file and os.path.exists(sync_from_local_yaml_file) == False:
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
        dbGaP, DB, project_mapping=project_mapping, storage_credentials=STORAGE_CREDENTIALS,
        is_sync_from_dbgap_server=is_sync_from_dbgap_server,
        sync_from_local_csv_dir=sync_from_local_csv_dir, sync_from_local_yaml_file=sync_from_local_yaml_file
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
                func.lower(User.username) == func.lower(user.username),
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
        user = s.query(User).filter(func.lower(User.username) == username.lower()).first()
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
    import fence.settings
    cirrus_config.update(**fence.settings.CIRRUS_CFG)

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
    import fence.settings
    cirrus_config.update(**fence.settings.CIRRUS_CFG)

    db = SQLAlchemyDriver(db)
    with db.session as current_session:
        client_service_accounts = (
            current_session.query(GoogleServiceAccount, Client).filter(
                GoogleServiceAccount.client_id == Client.client_id)
        )

        current_time = int(time.time())
        print('Current time: {}\n'.format(current_time))

        expired_sa_keys_for_users = (
            current_session.query(GoogleServiceAccountKey)
            .filter(
                GoogleServiceAccountKey
                .expires <= current_time)
        )

        with GoogleCloudManager() as g_mgr:
            # handle service accounts with default max expiration
            for service_account, client in client_service_accounts:
                g_mgr.handle_expired_service_account_keys(
                    service_account.google_unique_id)

            # handle service accounts with custom expiration
            for expired_user_key in expired_sa_keys_for_users:
                sa = (
                    current_session.query(GoogleServiceAccount)
                    .filter(
                        GoogleServiceAccount.id ==
                        expired_user_key.service_account_id).first()
                )
                response = g_mgr.delete_service_account_key(
                    account=sa.google_unique_id,
                    key_name=expired_user_key.key_id
                )
                response_error_code = response.get('error', {}).get('code')

                if not response_error_code:
                    current_session.delete(expired_user_key)
                    print(
                        'INFO: Removed expired service account key {} '
                        'for service account {} (owned by user with id {}).\n'
                        .format(expired_user_key.key_id, sa.email, sa.user_id)
                    )
                elif response_error_code == 404:
                    print(
                        'INFO: Service account key {} for service account {} '
                        '(owned by user with id {}) does not exist in Google. '
                        'Removing from database...\n'
                        .format(expired_user_key.key_id, sa.email, sa.user_id)
                    )
                    current_session.delete(expired_user_key)
                else:
                    print(
                        'ERROR: Google returned an error when attempting to '
                        'remove service account key {} '
                        'for service account {} (owned by user with id {}). '
                        'Error:\n{}\n'
                        .format(
                            expired_user_key.key_id, sa.email, sa.user_id,
                            response)
                    )


def remove_expired_google_accounts_from_proxy_groups(db):
    import fence.settings
    cirrus_config.update(**fence.settings.CIRRUS_CFG)

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
        lowercase_usernames = [x.lower() for x in usernames]
        users_to_delete = (
            session
            .query(User)
            .filter(func.lower(User.username).in_(lowercase_usernames))
            .all()
        )
        for user in users_to_delete:
            session.delete(user)
        session.commit()


def get_jwt_keypair(kid, root_dir):

    from fence.settings import JWT_KEYPAIR_FILES
    # cur_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    # par_dir = os.path.abspath(os.path.join(cur_dir, os.pardir))
    private_key = None

    if len(JWT_KEYPAIR_FILES) == 0:
        return None, None

    private_filepath = None
    if kid is None:
        private_filepath = os.path.join(
            root_dir, JWT_KEYPAIR_FILES.values()[0][1])
    else:
        for _kid, (_, private) in JWT_KEYPAIR_FILES.iteritems():
            if(kid != _kid):
                continue
            private_filepath = os.path.join(root_dir, private)

    if private_filepath is None:
        return None, None

    try:
        with open(private_filepath, 'r') as f:
            private_key = f.read()
    except IOError:
        private_key = None

    if kid:
        return kid, private_key
    else:
        return JWT_KEYPAIR_FILES.keys()[0], private_key


def create_user_token(DB, BASE_URL, ROOT_DIR, kid, token_type, username, scopes, expires_in=3600):
    try:
        if token_type == 'access_token':
            _, token, _ = create_user_access_token(
                DB, BASE_URL, ROOT_DIR, kid, username, scopes, expires_in)
            return token
        elif token_type == 'refresh_token':
            _, token, _ = create_user_refresh_token(
                DB, BASE_URL, ROOT_DIR, kid, username, scopes, expires_in)
            return token
        else:
            print('=============Option type is wrong!!!. Please select either access_token or refresh_token=============')
            return None
    except Exception as e:
        print(e.message)
        return None


def create_user_refresh_token(DB, BASE_URL, ROOT_DIR, kid, username, scopes, expires_in=3600):
    kid, private_key = get_jwt_keypair(kid=kid, root_dir=ROOT_DIR)
    if private_key is None:
        print("=========Can not find the private key !!!!==============")
        return None, None, None

    driver = SQLAlchemyDriver(DB)
    with driver.session as current_session:
        user = (current_session.query(User)
                .filter(func.lower(User.username) == username.lower())
                .first()
                )
        if not user:
            print('=========user is not existed !!!=============')
            return None, None, None

        headers = {'kid': kid}
        iat, exp = issued_and_expiration_times(expires_in)
        jti = str(uuid.uuid4())
        sub = str(user.id)
        claims = {
            'pur': 'refresh',
            'aud': scopes.split(','),
            'sub': sub,
            'iss': BASE_URL,
            'iat': iat,
            'exp': exp,
            'jti': jti,
            'context': {
                'user': {
                    'name': user.username,
                    'is_admin': user.is_admin,
                    'projects': dict(user.project_access),
                },
            },
        }

        token = to_unicode(jwt.encode(claims, private_key,
                                      headers=headers, algorithm='RS256'), 'UTF-8')
        current_session.add(
            UserRefreshToken(
                jti=claims['jti'], userid=user.id, expires=claims['exp']
            )
        )
        current_session.commit()
        return jti, token, claims


def create_user_access_token(DB, BASE_URL, ROOT_DIR, kid, username, scopes, expires_in=3600):
    kid, private_key = get_jwt_keypair(kid=kid, root_dir=ROOT_DIR)
    if private_key is None:
        print("=========Can not find the private key !!!!=============")
        return None, None, None

    driver = SQLAlchemyDriver(DB)
    with driver.session as current_session:
        user = (current_session.query(User)
                .filter(func.lower(User.username) == username.lower())
                .first()
                )
        if not user:
            print('=========user is not existed !!!=============')
            return None, None, None

        headers = {'kid': kid}
        iat, exp = issued_and_expiration_times(expires_in)
        jti = str(uuid.uuid4())
        sub = str(user.id)
        claims = {
            'pur': 'access',
            'aud': scopes.split(','),
            'sub': sub,
            'iss': BASE_URL,
            'iat': iat,
            'exp': exp,
            'jti': jti,
            'context': {
                'user': {
                    'name': user.username,
                    'is_admin': user.is_admin,
                    'projects': dict(user.project_access),
                },
            },
        }

        return jti, to_unicode(jwt.encode(claims, private_key, headers=headers, algorithm='RS256'), 'UTF-8'), claims


def link_bucket_to_project(db, bucket_id, bucket_provider, project_auth_id):
    """
    Associate a bucket to a specific project (with provided auth_id).

    Args:
        db (TYPE): database
        bucket_id (str): bucket db id or unique name
            WARNING: name uniqueness is only required for Google so it's not
                     a requirement of the db table. You will get an error if
                     there are multiple buckets with the given name. In that
                     case, you'll have to use the bucket's id.
        bucket_provider (str): CloudProvider.name for the bucket
        project_auth_id (str): Project.auth_id to link to bucket
    """
    driver = SQLAlchemyDriver(db)
    with driver.session as current_session:
        google_cloud_provider = (
            current_session.query(
                CloudProvider).filter_by(name=bucket_provider).first()
        )
        if not google_cloud_provider:
            raise NameError(
                'No bucket with provider "{}" exists.'
                .format(bucket_provider)
            )

        # first try by searching using id
        try:
            bucket_id = int(bucket_id)
            bucket_db_entry = (
                current_session.query(Bucket)
                .filter_by(
                    id=bucket_id,
                    provider_id=google_cloud_provider.id)
            ).first()
        except ValueError:
            # invalid id, must be int
            bucket_db_entry = None

        # nothing found? try searching for single bucket with name bucket_id
        if not bucket_db_entry:
            buckets_by_name = (
                current_session.query(Bucket)
                .filter_by(
                    name=bucket_id,
                    provider_id=google_cloud_provider.id)
            )
            # don't get a bucket if the name isn't unique. NOTE: for Google,
            # these have to be globally unique so they'll be unique here.
            buckets_with_name = buckets_by_name.count()
            if buckets_with_name == 1:
                bucket_db_entry = buckets_by_name[0]
            elif buckets_with_name > 1:
                raise NameError(
                    'No bucket with id "{bucket_id}" exists. Tried buckets '
                    'with name "{bucket_id}", but this returned multiple '
                    'buckets. Please specify the id from the db and not just '
                    'the name.'.format(bucket_id=bucket_id)
                )
            else:
                # keep bucket_db_entry as None
                pass

        if not bucket_db_entry:
            raise NameError(
                'No bucket with id or name "{}" exists.'
                .format(bucket_id)
            )

        project_db_entry = (
            current_session.query(
                Project).filter_by(auth_id=project_auth_id).first()
        )
        if not project_db_entry:
            raise NameError(
                'No project with auth_id "{}" exists.'
                .format(project_auth_id)
            )

        project_linkage = ProjectToBucket(
            project_id=project_db_entry.id,
            bucket_id=bucket_db_entry.id,
            privilege=['owner']  # TODO What should this be???
        )
        current_session.add(project_linkage)
        current_session.commit()


def create_google_bucket(
        db, name, storage_class=None, public=False, requester_pays=False,
        google_project_id=None, project_auth_id=None, access_logs_bucket=None,
        allowed_privileges=None):
    """
    Create a Google bucket and populate database with necessary information.

    If the bucket is not public, this will also create a Google Bucket Access
    Group(s) to control access to the new bucket. In order to give access
    to a new user, simply add them to the Google Bucket Access Group.

    NOTE: At the moment, a different Google Bucket Access Group is created
          for each different privilege in allowed_privileges (which defaults
          to ['read', 'write']). So there will be separate Google Groups for
          each access level.

    Args:
        db (TYPE): database
        name (str): name for the bucket, must be globally unique throughout Google
        storage_class (str): enum, one of the cirrus's GOOGLE_STORAGE_CLASSES
        public (bool, optional): whether or not the bucket should be public
        requester_pays (bool, optional): Whether or not to enable requester_pays
            on the bucket
        google_project_id (str, optional): Google project this bucket should be
            associated with
        project_auth_id (str, optional): a Project.auth_id to associate this
            bucket with. The project must exist in the db already.
        access_logs_bucket (str, optional): Enables logging. Must provide a
            Google bucket name which will store the access logs
        allowed_privileges (List(str), optional): privileges to allow on
            the bucket. Defaults to ['read', 'write']. Also allows:
            ['admin'] for all permission on the bucket including delete,
            ['read'] for viewing access,
            ['write'] for creation rights but not viewing access
    """
    import fence.settings
    cirrus_config.update(**fence.settings.CIRRUS_CFG)

    google_project_id = google_project_id or cirrus_config.GOOGLE_PROJECT_ID

    # default to read access
    allowed_privileges = allowed_privileges or ['read', 'write']

    driver = SQLAlchemyDriver(db)
    with driver.session as current_session:
        # use storage creds to create bucket
        # (default creds don't have permission)
        bucket_db_entry = (
            _create_google_bucket_and_update_db(
                db_session=current_session,
                name=name,
                storage_class=storage_class,
                requester_pays=requester_pays,
                google_project_id=google_project_id,
                public=public,
                project_auth_id=project_auth_id,
                access_logs_bucket=access_logs_bucket)
        )

        if not public:
            for privilege in allowed_privileges:
                _create_google_bucket_access_group(
                    db_session=current_session,
                    google_bucket_name=name,
                    bucket_db_id=bucket_db_entry.id,
                    google_project_id=google_project_id,
                    privileges=[privilege])


def _create_google_bucket_and_update_db(
        db_session, name, storage_class, public, requester_pays,
        google_project_id, project_auth_id, access_logs_bucket):
    """
    Handles creates the Google bucket and adding necessary db entry
    """
    manager = GoogleCloudManager(
        google_project_id, creds=cirrus_config.configs['GOOGLE_STORAGE_CREDS'])
    with manager as g_mgr:
        g_mgr.create_bucket(
            name,
            storage_class=storage_class,
            public=public,
            requester_pays=requester_pays,
            access_logs_bucket=access_logs_bucket)

        # add bucket to db
        google_cloud_provider = (
            db_session.query(
                CloudProvider).filter_by(name='google').first()
        )
        if not google_cloud_provider:
            google_cloud_provider = CloudProvider(
                name='google',
                description='Google Cloud Platform',
                service='general')
            db_session.add(google_cloud_provider)
            db_session.commit()

        bucket_db_entry = Bucket(
            name=name,
            provider_id=google_cloud_provider.id
        )
        db_session.add(bucket_db_entry)
        db_session.commit()

        print('Successfully created Google Bucket {}.'.format(name))

        # optionally link this new bucket to an existing project
        if project_auth_id:
            project_db_entry = (
                db_session.query(
                    Project).filter_by(auth_id=project_auth_id).first()
            )
            if project_db_entry:
                project_linkage = ProjectToBucket(
                    project_id=project_db_entry.id,
                    bucket_id=bucket_db_entry.id,
                    privilege=['owner']  # TODO What should this be???
                )
                db_session.add(project_linkage)
                db_session.commit()

    return bucket_db_entry


def _create_google_bucket_access_group(
        db_session, google_bucket_name, bucket_db_id, google_project_id,
        privileges):
    access_group = None

    # use default creds for creating group and iam policies
    with GoogleCloudManager(google_project_id) as g_mgr:
        # create bucket access group
        result = g_mgr.create_group(
            name=google_bucket_name + '_' + '_'.join(privileges) + '_gbag')
        group_email = result['email']

        # add bucket group to db
        access_group = GoogleBucketAccessGroup(
            bucket_id=bucket_db_id,
            email=group_email,
            privileges=privileges
        )
        db_session.add(access_group)
        db_session.commit()

        g_mgr.give_group_access_to_bucket(
            group_email, google_bucket_name, access=privileges)

        print(
            'Successfully created Google Bucket Access Group {} '
            'for Google Bucket {}.'
            .format(group_email, google_bucket_name)
        )

    return access_group
