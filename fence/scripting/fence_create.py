from datetime import datetime, timedelta
import os
import os.path
import requests
import time
from yaml import safe_load
import json
import pprint
import asyncio

from alembic.config import main as alembic_main
from gen3cirrus import GoogleCloudManager
from gen3cirrus.google_cloud.errors import GoogleAuthError
from gen3cirrus.config import config as cirrus_config
from cdislogging import get_logger
from sqlalchemy import func
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
    ProjectToBucket,
)
from sqlalchemy import and_

from fence.blueprints.link import (
    force_update_user_google_account_expiration,
    add_new_user_google_account,
)
from fence.errors import Unauthorized
from fence.jwt.token import (
    generate_signed_access_token,
    generate_signed_refresh_token,
    issued_and_expiration_times,
)
from fence.job.access_token_updater import TokenAndAuthUpdater
from fence.models import (
    Client,
    GoogleServiceAccount,
    GoogleServiceAccountKey,
    UserGoogleAccount,
    UserGoogleAccountToProxyGroup,
    GoogleBucketAccessGroup,
    GoogleProxyGroupToGoogleBucketAccessGroup,
    UserRefreshToken,
    ServiceAccountToGoogleBucketAccessGroup,
    query_for_user,
    GA4GHVisaV1,
    get_client_expires_at,
)
from fence.scripting.google_monitor import email_users_without_access, validation_check
from fence.config import config
from fence.sync.sync_users import UserSyncer
from fence.utils import (
    create_client,
    get_valid_expiration,
    generate_client_credentials,
    get_SQLAlchemyDriver,
)
from sqlalchemy.orm.attributes import flag_modified
from gen3authz.client.arborist.client import ArboristClient

logger = get_logger(__name__)


def list_client_action(db):
    try:
        driver = get_SQLAlchemyDriver(db)
        with driver.session as s:
            for row in s.query(Client).all():
                pprint.pprint(row.__dict__)
    except Exception as e:
        logger.error(str(e))


def modify_client_action(
    DB,
    client=None,
    delete_urls=False,
    urls=None,
    name=None,
    description=None,
    set_auto_approve=False,
    unset_auto_approve=False,
    arborist=None,
    policies=None,
    allowed_scopes=None,
    append=False,
    expires_in=None,
):
    driver = get_SQLAlchemyDriver(DB)
    with driver.session as s:
        client_name = client
        clients = s.query(Client).filter(Client.name == client_name).all()
        if not clients:
            raise Exception("client {} does not exist".format(client_name))
        for client in clients:
            metadata = client.client_metadata
            if urls:
                if append:
                    metadata["redirect_uris"] += urls
                    logger.info("Adding {} to urls".format(urls))
                else:
                    if isinstance(urls, list):
                        metadata["redirect_uris"] = urls
                    else:
                        metadata["redirect_uris"] = [urls]
                    logger.info("Changing urls to {}".format(urls))
            if delete_urls:
                metadata["redirect_uris"] = []
                logger.info("Deleting urls")
            if set_auto_approve:
                client.auto_approve = True
                logger.info("Auto approve set to True")
            if unset_auto_approve:
                client.auto_approve = False
                logger.info("Auto approve set to False")
            if name:
                client.name = name
                logger.info("Updating name to {}".format(name))
            if description:
                client.description = description
                logger.info("Updating description to {}".format(description))
            if allowed_scopes:
                if append:
                    new_scopes = client.scope.split() + allowed_scopes
                    metadata["scope"] = " ".join(new_scopes)
                    logger.info("Adding {} to allowed_scopes".format(allowed_scopes))
                else:
                    metadata["scope"] = " ".join(allowed_scopes)
                    logger.info("Updating allowed_scopes to {}".format(allowed_scopes))
            if expires_in:
                client.expires_at = get_client_expires_at(
                    expires_in=expires_in, grant_types=client.grant_types
                )
            # Call setter on Json object to persist changes if any
            client.set_client_metadata(metadata)
        s.commit()
        if arborist is not None and policies:
            arborist.update_client(client.client_id, policies)


def create_client_action(
    DB,
    username=None,
    client=None,
    urls=None,
    auto_approve=False,
    expires_in=None,
    **kwargs,
):
    print("\nSave these credentials! Fence will not save the unhashed client secret.")
    res = create_client(
        DB=DB,
        username=username,
        urls=urls,
        name=client,
        auto_approve=auto_approve,
        expires_in=expires_in,
        **kwargs,
    )
    print("client id, client secret:")
    # This should always be the last line of output and should remain in this format--
    # cloud-auto and gen3-qa use the output programmatically.
    print(res)


def delete_client_action(DB, client_name):
    try:
        cirrus_config.update(**config["CIRRUS_CFG"])
    except AttributeError:
        # no cirrus config, continue anyway. we don't have client service accounts
        # to delete
        pass

    try:
        driver = get_SQLAlchemyDriver(DB)
        with driver.session as current_session:
            if (
                not current_session.query(Client)
                .filter(Client.name == client_name)
                .first()
            ):
                raise Exception("client {} does not exist".format(client_name))

            clients = (
                current_session.query(Client).filter(Client.name == client_name).all()
            )

            for client in clients:
                _remove_client_service_accounts(current_session, client)
                current_session.delete(client)
            current_session.commit()

        logger.info("Client '{}' deleted".format(client_name))
    except Exception as e:
        logger.error(str(e))


def delete_expired_clients_action(DB, slack_webhook=None, warning_days=None):
    """
    Args:
        slack_webhook (str): Slack webhook to post warnings when clients expired or are about to expire
        warning_days (int): how many days before a client expires should we post a warning on
            Slack (default: 7)
    """
    try:
        cirrus_config.update(**config["CIRRUS_CFG"])
    except AttributeError:
        # no cirrus config, continue anyway. we don't have client service accounts
        # to delete
        pass

    def format_uris(uris):
        if not uris or uris == [None]:
            return uris
        return " ".join(uris)

    now = datetime.now().timestamp()
    driver = get_SQLAlchemyDriver(DB)
    expired_messages = ["Some expired OIDC clients have been deleted!"]
    with driver.session as current_session:
        clients = (
            current_session.query(Client)
            # for backwards compatibility, 0 means no expiration
            .filter(Client.expires_at != 0)
            .filter(Client.expires_at <= now)
            .all()
        )

        for client in clients:
            expired_messages.append(
                f"Client '{client.name}' (ID '{client.client_id}') expired at {datetime.fromtimestamp(client.expires_at)} UTC. Redirect URIs: {format_uris(client.redirect_uris)})"
            )
            _remove_client_service_accounts(current_session, client)
            current_session.delete(client)
            current_session.commit()

        # get the clients that are expiring soon
        warning_days = float(warning_days) if warning_days else 7
        warning_days_in_secs = warning_days * 24 * 60 * 60  # days to seconds
        warning_expiry = (
            datetime.utcnow() + timedelta(seconds=warning_days_in_secs)
        ).timestamp()
        expiring_clients = (
            current_session.query(Client)
            .filter(Client.expires_at != 0)
            .filter(Client.expires_at <= warning_expiry)
            .all()
        )

    expiring_messages = ["Some OIDC clients are expiring soon!"]
    expiring_messages.extend(
        [
            f"Client '{client.name}' (ID '{client.client_id}') expires at {datetime.fromtimestamp(client.expires_at)} UTC. Redirect URIs: {format_uris(client.redirect_uris)}"
            for client in expiring_clients
        ]
    )

    for post_msgs, nothing_to_do_msg in (
        (expired_messages, "No expired clients to delete"),
        (expiring_messages, "No clients are close to expiring"),
    ):
        if len(post_msgs) > 1:
            for e in post_msgs:
                logger.info(e)
            if slack_webhook:  # post a warning on Slack
                logger.info("Posting to Slack...")
                payload = {
                    "attachments": [
                        {
                            "fallback": post_msgs[0],
                            "title": post_msgs[0],
                            "text": "\n- " + "\n- ".join(post_msgs[1:]),
                            "color": "#FF5F15",
                        }
                    ]
                }
                resp = requests.post(slack_webhook, json=payload)
                resp.raise_for_status()
        else:
            logger.info(nothing_to_do_msg)


def rotate_client_action(DB, client_name, expires_in=None):
    """
    Rorate a client's credentials (client ID and secret). The old credentials are
    NOT deactivated and must be deleted or expired separately. This allows for a
    rotation without downtime.

    Args:
        DB (str): database connection string
        client_name (str): name of the client to rotate credentials for
        expires_in (optional): number of days until this client expires (by default, no expiration)

    Returns:
        This functions does not return anything, but it prints the new set of credentials.
    """
    driver = get_SQLAlchemyDriver(DB)
    with driver.session as s:
        client = s.query(Client).filter(Client.name == client_name).first()
        if not client:
            raise Exception("client {} does not exist".format(client_name))

        # create a new row in the DB for the same client, with a new ID, secret and expiration
        client_id, client_secret, hashed_secret = generate_client_credentials(
            client.is_confidential
        )
        client = Client(
            client_id=client_id,
            client_secret=hashed_secret,
            expires_in=expires_in,
            # the rest is identical to the client being rotated
            user=client.user,
            redirect_uris=client.redirect_uris,
            allowed_scopes=client.scope,
            description=client.description,
            name=client.name,
            auto_approve=client.auto_approve,
            grant_types=client.grant_types,
            is_confidential=client.is_confidential,
            token_endpoint_auth_method=client.token_endpoint_auth_method,
        )
        s.add(client)
        s.commit()

    res = (client_id, client_secret)
    print(
        f"\nSave these credentials! Fence will not save the unhashed client secret.\nclient id, client secret:\n{res}"
    )


def _remove_client_service_accounts(db_session, client):
    client_service_accounts = (
        db_session.query(GoogleServiceAccount)
        .filter(GoogleServiceAccount.client_id == client.client_id)
        .all()
    )

    if client_service_accounts:
        with GoogleCloudManager() as g_mgr:
            for service_account in client_service_accounts:
                logger.info(
                    "Deleting client {}'s service account: {}".format(
                        client.name, service_account.email
                    )
                )
                response = g_mgr.delete_service_account(service_account.email)
                if not response.get("error"):
                    db_session.delete(service_account)
                    db_session.commit()
                else:
                    logger.error("ERROR - from Google: {}".format(response))
                    logger.error(
                        "ERROR - Could not delete client service account: {}".format(
                            service_account.email
                        )
                    )


def get_default_init_syncer_inputs(authz_provider):
    DB = os.environ.get("FENCE_DB") or config.get("DB")
    if DB is None:
        try:
            from fence.settings import DB
        except ImportError:
            pass

    arborist = ArboristClient(
        arborist_base_url=config["ARBORIST"],
        logger=get_logger("user_syncer.arborist_client"),
        authz_provider=authz_provider,
    )
    dbGaP = os.environ.get("dbGaP") or config.get("dbGaP")
    if not isinstance(dbGaP, list):
        dbGaP = [dbGaP]

    storage_creds = config["STORAGE_CREDENTIALS"]

    return {
        "DB": DB,
        "arborist": arborist,
        "dbGaP": dbGaP,
        "STORAGE_CREDENTIALS": storage_creds,
    }


def init_syncer(
    dbGaP,
    STORAGE_CREDENTIALS,
    DB,
    projects=None,
    is_sync_from_dbgap_server=False,
    sync_from_local_csv_dir=None,
    sync_from_local_yaml_file=None,
    json_from_api=None,
    arborist=None,
    folder=None,
):
    """
    sync ACL files from dbGap to auth db and storage backends
    imports from config is done here because dbGap is
    an optional requirement for fence so it might not be specified
    in config
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
    """
    try:
        cirrus_config.update(**config["CIRRUS_CFG"])
    except AttributeError:
        # no cirrus config, continue anyway. Google APIs will probably fail.
        # this is okay if users don't need access to Google buckets
        pass

    if projects is not None and not os.path.exists(projects):
        logger.error("====={} is not found!!!=======".format(projects))
        return
    if sync_from_local_csv_dir and not os.path.exists(sync_from_local_csv_dir):
        logger.error("====={} is not found!!!=======".format(sync_from_local_csv_dir))
        return
    if sync_from_local_yaml_file and not os.path.exists(sync_from_local_yaml_file):
        logger.error("====={} is not found!!!=======".format(sync_from_local_yaml_file))
        return

    project_mapping = None
    if projects:
        try:
            with open(projects, "r") as f:
                project_mapping = safe_load(f)
        except IOError:
            pass

    return UserSyncer(
        dbGaP=dbGaP,
        DB=DB,
        project_mapping=project_mapping,
        storage_credentials=STORAGE_CREDENTIALS,
        is_sync_from_dbgap_server=is_sync_from_dbgap_server,
        sync_from_local_csv_dir=sync_from_local_csv_dir,
        sync_from_local_yaml_file=sync_from_local_yaml_file,
        json_from_api=json_from_api,
        arborist=arborist,
        folder=folder,
    )


def download_dbgap_files(
    # Note: need to keep all parameter to prevent download failure
    dbGaP,
    STORAGE_CREDENTIALS,
    DB,
    projects=None,
    is_sync_from_dbgap_server=False,
    sync_from_local_csv_dir=None,
    sync_from_local_yaml_file=None,
    arborist=None,
    folder=None,
):
    syncer = init_syncer(
        dbGaP,
        STORAGE_CREDENTIALS,
        DB,
        projects,
        is_sync_from_dbgap_server,
        sync_from_local_csv_dir,
        sync_from_local_yaml_file,
        arborist,
        folder,
    )
    if not syncer:
        exit(1)
    syncer.download()


def sync_users(
    dbGaP,
    STORAGE_CREDENTIALS,
    DB,
    projects=None,
    is_sync_from_dbgap_server=False,
    sync_from_local_csv_dir=None,
    sync_from_local_yaml_file=None,
    json_from_api=None,
    arborist=None,
    folder=None,
):
    syncer = init_syncer(
        dbGaP=dbGaP,
        STORAGE_CREDENTIALS=STORAGE_CREDENTIALS,
        DB=DB,
        projects=projects,
        is_sync_from_dbgap_server=is_sync_from_dbgap_server,
        sync_from_local_csv_dir=sync_from_local_csv_dir,
        sync_from_local_yaml_file=sync_from_local_yaml_file,
        json_from_api=json_from_api,
        arborist=arborist,
        folder=folder,
    )
    if not syncer:
        exit(1)
    syncer.sync()


def create_sample_data(DB, yaml_file_path):
    with open(yaml_file_path, "r") as f:
        data = safe_load(f)

    db = get_SQLAlchemyDriver(DB)
    with db.session as s:
        create_cloud_providers(s, data)
        create_projects(s, data)
        create_group(s, data)
        create_users_with_group(DB, s, data)


def create_group(s, data):
    groups = data.get("groups", {})
    for group_name, fields in groups.items():
        projects = fields.get("projects", [])
        group = s.query(Group).filter(Group.name == group_name).first()
        if not group:
            group = Group(name=group_name)
            s.add(group)
        for project_data in projects:
            grant_project_to_group_or_user(s, project_data, group)


def create_projects(s, data):
    projects = data.get("projects", [])
    for project in projects:
        create_project(s, project)


def create_project(s, project_data):
    auth_id = project_data["auth_id"]
    name = project_data.get("name", auth_id)
    project = s.query(Project).filter_by(name=name).first()
    if project is None:
        project = Project(name=name, auth_id=auth_id)
        s.add(project)
    if "storage_accesses" in project_data:
        sa_list = project_data.get("storage_accesses", [])
        for storage_access in sa_list:
            provider = storage_access["name"]
            buckets = storage_access.get("buckets", [])
            sa = (
                s.query(StorageAccess)
                .join(StorageAccess.provider, StorageAccess.project)
                .filter(Project.name == project.name)
                .filter(CloudProvider.name == provider)
                .first()
            )
            c_provider = s.query(CloudProvider).filter_by(name=provider).first()
            assert c_provider, "CloudProvider {} does not exist".format(provider)
            if not sa:
                sa = StorageAccess(provider=c_provider, project=project)
                s.add(sa)
                logger.info(
                    "created storage access for {} to {}".format(
                        project.name, c_provider.name
                    )
                )
            for bucket in buckets:
                b = (
                    s.query(Bucket)
                    .filter_by(name=bucket)
                    .join(Bucket.provider)
                    .filter(CloudProvider.name == provider)
                    .first()
                )
                if not b:
                    b = Bucket(name=bucket)
                    b.provider = c_provider
                    s.add(b)
                    logger.info("created bucket {} in db".format(bucket))

    return project


def grant_project_to_group_or_user(s, project_data, group=None, user=None):
    privilege = project_data.get("privilege", [])
    project = create_project(s, project_data)
    if group:
        ap = (
            s.query(AccessPrivilege)
            .join(AccessPrivilege.project)
            .join(AccessPrivilege.group)
            .filter(Project.name == project.name, Group.name == group.name)
            .first()
        )
        name = group.name
    elif user:
        ap = (
            s.query(AccessPrivilege)
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
        raise Exception("need to provide either a user or group")
    if not ap:
        if group:
            ap = AccessPrivilege(project=project, group=group, privilege=privilege)
        elif user:
            ap = AccessPrivilege(project=project, user=user, privilege=privilege)
        else:
            raise Exception("need to provide either a user or group")
        s.add(ap)
        logger.info(
            "created access privilege {} of project {} to {}".format(
                privilege, project.name, name
            )
        )
    else:
        ap.privilege = privilege
        logger.info(
            "updated access privilege {} of project {} to {}".format(
                privilege, project.name, name
            )
        )


def create_cloud_providers(s, data):
    cloud_data = data.get("cloud_providers", {})
    for name, fields in cloud_data.items():
        cloud_provider = (
            s.query(CloudProvider).filter(CloudProvider.name == name).first()
        )
        if not cloud_provider:
            cloud_provider = CloudProvider(
                name=name,
                backend=fields.get("backend", "cleversafe"),
                service=fields.get("service", "storage"),
            )
            s.add(cloud_provider)


def create_users_with_group(DB, s, data):
    providers = {}
    data_groups = data.get("groups", {})
    users = data.get("users", {})
    for username, data in users.items():
        is_existing_user = True
        user = query_for_user(session=s, username=username)

        admin = data.get("admin", False)

        if not user:
            is_existing_user = False
            provider_name = data.get("provider", "google")
            provider = providers.get(provider_name)
            if not provider:
                provider = (
                    s.query(IdentityProvider)
                    .filter(IdentityProvider.name == provider_name)
                    .first()
                )
                providers[provider_name] = provider
                if not provider:
                    raise Exception("provider {} not found".format(provider_name))

            user = User(username=username, idp_id=provider.id, is_admin=admin)
        user.is_admin = admin
        group_names = data.get("groups", [])
        for group_name in group_names:
            assign_group_to_user(s, user, group_name, data_groups[group_name])
        projects = data.get("projects", [])
        for project in projects:
            grant_project_to_group_or_user(s, project, user=user)
        if not is_existing_user:
            s.add(user)
        for client in data.get("clients", []):
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
    """
    DEPRECATED - Initial user proxy group / service account creation.
    No longer necessary as proxy groups and service accounts are lazily
    created.
    """
    pass


def remove_expired_google_service_account_keys(db):
    cirrus_config.update(**config["CIRRUS_CFG"])

    db = get_SQLAlchemyDriver(db)
    with db.session as current_session:
        client_service_accounts = current_session.query(
            GoogleServiceAccount, Client
        ).filter(GoogleServiceAccount.client_id == Client.client_id)

        current_time = int(time.time())
        logger.info("Current time: {}\n".format(current_time))

        expired_sa_keys_for_users = current_session.query(
            GoogleServiceAccountKey
        ).filter(GoogleServiceAccountKey.expires <= current_time)

        with GoogleCloudManager() as g_mgr:
            # handle service accounts with default max expiration
            for service_account, client in client_service_accounts:
                g_mgr.handle_expired_service_account_keys(service_account.email)

            # handle service accounts with custom expiration
            for expired_user_key in expired_sa_keys_for_users:
                logger.info("expired_user_key: {}\n".format(expired_user_key))
                sa = (
                    current_session.query(GoogleServiceAccount)
                    .filter(
                        GoogleServiceAccount.id == expired_user_key.service_account_id
                    )
                    .first()
                )

                response = g_mgr.delete_service_account_key(
                    account=sa.email, key_name=expired_user_key.key_id
                )
                response_error_code = response.get("error", {}).get("code")
                response_error_status = response.get("error", {}).get("status")
                logger.info("response_error_code: {}\n".format(response_error_code))
                logger.info("response_error_status: {}\n".format(response_error_status))

                if not response_error_code:
                    current_session.delete(expired_user_key)
                    logger.info(
                        "INFO: Removed expired service account key {} "
                        "for service account {} (owned by user with id {}).\n".format(
                            expired_user_key.key_id, sa.email, sa.user_id
                        )
                    )
                elif (
                    response_error_code == 404
                    or response_error_status == "FAILED_PRECONDITION"
                ):
                    logger.info(
                        "INFO: Service account key {} for service account {} "
                        "(owned by user with id {}) does not exist in Google. "
                        "Removing from database...\n".format(
                            expired_user_key.key_id, sa.email, sa.user_id
                        )
                    )
                    current_session.delete(expired_user_key)
                else:
                    logger.error(
                        "ERROR: Google returned an error when attempting to "
                        "remove service account key {} "
                        "for service account {} (owned by user with id {}). "
                        "Error:\n{}\n".format(
                            expired_user_key.key_id, sa.email, sa.user_id, response
                        )
                    )


def remove_expired_google_accounts_from_proxy_groups(db):
    cirrus_config.update(**config["CIRRUS_CFG"])

    db = get_SQLAlchemyDriver(db)
    with db.session as current_session:
        current_time = int(time.time())
        logger.info("Current time: {}".format(current_time))

        expired_accounts = current_session.query(UserGoogleAccountToProxyGroup).filter(
            UserGoogleAccountToProxyGroup.expires <= current_time
        )

        with GoogleCloudManager() as g_mgr:
            for expired_account_access in expired_accounts:
                g_account = (
                    current_session.query(UserGoogleAccount)
                    .filter(
                        UserGoogleAccount.id
                        == expired_account_access.user_google_account_id
                    )
                    .first()
                )
                try:
                    response = g_mgr.remove_member_from_group(
                        member_email=g_account.email,
                        group_id=expired_account_access.proxy_group_id,
                    )
                    response_error_code = response.get("error", {}).get("code")

                    if not response_error_code:
                        current_session.delete(expired_account_access)
                        logger.info(
                            "INFO: Removed {} from proxy group with id {}.\n".format(
                                g_account.email, expired_account_access.proxy_group_id
                            )
                        )
                    else:
                        logger.error(
                            "ERROR: Google returned an error when attempting to "
                            "remove member {} from proxy group {}. Error:\n{}\n".format(
                                g_account.email,
                                expired_account_access.proxy_group_id,
                                response,
                            )
                        )
                except Exception as exc:
                    logger.error(
                        "ERROR: Google returned an error when attempting to "
                        "remove member {} from proxy group {}. Error:\n{}\n".format(
                            g_account.email, expired_account_access.proxy_group_id, exc
                        )
                    )


def delete_users(DB, usernames):
    driver = get_SQLAlchemyDriver(DB)
    with driver.session as session:
        # NOTE that calling ``.delete()`` on the query itself will not follow
        # cascade deletion rules set up in any relationships.
        lowercase_usernames = [x.lower() for x in usernames]
        users_to_delete = (
            session.query(User)
            .filter(func.lower(User.username).in_(lowercase_usernames))
            .all()
        )
        for user in users_to_delete:
            session.delete(user)
        session.commit()


def cleanup_expired_ga4gh_information(DB):
    """
    Remove any expired passports/visas from the database if they're expired.

    IMPORTANT NOTE: This DOES NOT actually remove authorization, it assumes that the
                    same expiration was set and honored in the authorization system.
    """
    driver = get_SQLAlchemyDriver(DB)
    with driver.session as session:
        current_time = int(time.time())

        # Get expires field from db, if None default to NOT expired
        records_to_delete = (
            session.query(GA4GHVisaV1)
            .filter(
                and_(
                    GA4GHVisaV1.expires.isnot(None),
                    GA4GHVisaV1.expires < current_time,
                )
            )
            .all()
        )
        num_deleted_records = 0
        if records_to_delete:
            for record in records_to_delete:
                try:
                    session.delete(record)
                    session.commit()

                    num_deleted_records += 1
                except Exception as e:
                    logger.error(
                        "ERROR: Could not remove GA4GHVisaV1 with id={}. Detail {}".format(
                            record.id, e
                        )
                    )

        logger.info(
            f"Removed {num_deleted_records} expired GA4GHVisaV1 records from db."
        )


def delete_expired_google_access(DB):
    """
    Delete all expired Google data access (e.g. remove proxy groups from Google Bucket
    Access Groups if expired).
    """
    cirrus_config.update(**config["CIRRUS_CFG"])

    driver = get_SQLAlchemyDriver(DB)
    with driver.session as session:
        current_time = int(time.time())

        # Get expires field from db, if None default to NOT expired
        records_to_delete = (
            session.query(GoogleProxyGroupToGoogleBucketAccessGroup)
            .filter(
                and_(
                    GoogleProxyGroupToGoogleBucketAccessGroup.expires.isnot(None),
                    GoogleProxyGroupToGoogleBucketAccessGroup.expires < current_time,
                )
            )
            .all()
        )
        num_deleted_records = 0
        if records_to_delete:
            with GoogleCloudManager() as manager:
                for record in records_to_delete:
                    try:
                        member_email = record.proxy_group.email
                        access_group_email = record.access_group.email
                        manager.remove_member_from_group(
                            member_email, access_group_email
                        )
                        logger.info(
                            "Removed {} from {}, expired {}. Current time: {} ".format(
                                member_email,
                                access_group_email,
                                record.expires,
                                current_time,
                            )
                        )
                        session.delete(record)
                        session.commit()

                        num_deleted_records += 1
                    except Exception as e:
                        logger.error(
                            "ERROR: Could not remove Google group member {} from access group {}. Detail {}".format(
                                member_email, access_group_email, e
                            )
                        )

        logger.info(
            f"Removed {num_deleted_records} expired Google Access records from db and Google."
        )


def delete_expired_service_accounts(DB):
    """
    Delete all expired service accounts.
    """
    cirrus_config.update(**config["CIRRUS_CFG"])

    driver = get_SQLAlchemyDriver(DB)
    with driver.session as session:
        current_time = int(time.time())
        records_to_delete = (
            session.query(ServiceAccountToGoogleBucketAccessGroup)
            .filter(ServiceAccountToGoogleBucketAccessGroup.expires < current_time)
            .all()
        )
        if len(records_to_delete):
            with GoogleCloudManager() as manager:
                for record in records_to_delete:
                    try:
                        manager.remove_member_from_group(
                            record.service_account.email, record.access_group.email
                        )
                        session.delete(record)
                        logger.info(
                            "Removed expired service account: {}".format(
                                record.service_account.email
                            )
                        )
                    except Exception as e:
                        logger.error(
                            "ERROR: Could not delete service account {}. Details: {}".format(
                                record.service_account.email, e
                            )
                        )

                session.commit()


def verify_bucket_access_group(DB):
    """
    Go through all the google group members, remove them from Google group and Google
    user service account if they are not in Fence

    Args:
        DB(str): db connection string

    Returns:
        None

    """
    cirrus_config.update(**config["CIRRUS_CFG"])

    driver = get_SQLAlchemyDriver(DB)
    with driver.session as session:
        access_groups = session.query(GoogleBucketAccessGroup).all()
        with GoogleCloudManager() as manager:
            for access_group in access_groups:
                try:
                    members = manager.get_group_members(access_group.email)
                    logger.debug(f"google group members response: {members}")
                except GoogleAuthError as e:
                    logger.error("ERROR: Authentication error!!!. Detail {}".format(e))
                    return
                except Exception as e:
                    logger.error(
                        "ERROR: Could not list group members of {}. Detail {}".format(
                            access_group.email, e
                        )
                    )
                    return

                for member in members:
                    if member.get("type") == "GROUP":
                        _verify_google_group_member(session, access_group, member)
                    elif member.get("type") == "USER":
                        _verify_google_service_account_member(
                            session, access_group, member
                        )


def _verify_google_group_member(session, access_group, member):
    """
    Delete if the member which is a google group is not in Fence.

    Args:
        session(Session): db session
        access_group(GoogleBucketAccessGroup): access group
        member(dict): group member info

    Returns:
        None

    """
    account_emails = [
        granted_group.proxy_group.email
        for granted_group in (
            session.query(GoogleProxyGroupToGoogleBucketAccessGroup)
            .filter_by(access_group_id=access_group.id)
            .all()
        )
    ]

    if not any([email for email in account_emails if email == member.get("email")]):
        try:
            with GoogleCloudManager() as manager:
                manager.remove_member_from_group(
                    member.get("email"), access_group.email
                )
                logger.info(
                    "Removed {} from {}, not found in fence but found "
                    "in Google Group.".format(member.get("email"), access_group.email)
                )
        except Exception as e:
            logger.error(
                "ERROR: Could not remove google group memeber {} from access group {}. Detail {}".format(
                    member.get("email"), access_group.email, e
                )
            )


def _verify_google_service_account_member(session, access_group, member):
    """
    Delete if the member which is a service account is not in Fence.

    Args:
        session(session): db session
        access_group(GoogleBucketAccessGroup): access group
        members(dict): service account member info

    Returns:
        None

    """

    account_emails = [
        account.service_account.email
        for account in (
            session.query(ServiceAccountToGoogleBucketAccessGroup)
            .filter_by(access_group_id=access_group.id)
            .all()
        )
    ]

    if not any([email for email in account_emails if email == member.get("email")]):
        try:
            with GoogleCloudManager() as manager:
                manager.remove_member_from_group(
                    member.get("email"), access_group.email
                )
                logger.info(
                    "Removed {} from {}, not found in fence but found "
                    "in Google Group.".format(member.get("email"), access_group.email)
                )
        except Exception as e:
            logger.error(
                "ERROR: Could not remove service account memeber {} from access group {}. Detail {}".format(
                    member.get("email"), access_group.email, e
                )
            )


class JWTCreator(object):
    required_kwargs = ["kid", "private_key", "username", "scopes"]
    all_kwargs = required_kwargs + ["expires_in", "client_id"]

    default_expiration = 3600

    def __init__(self, db, base_url, **kwargs):
        self.db = db
        self.base_url = base_url

        # These get assigned values just below here, with setattr. Defined here
        # so linters won't complain they're undefined.
        self.kid = None
        self.private_key = None
        self.username = None
        self.scopes = None
        self.client_id = None

        for required_kwarg in self.required_kwargs:
            if required_kwarg not in kwargs:
                raise ValueError("missing required argument: " + required_kwarg)

        # Set attributes on this object from the kwargs.
        for kwarg_name in self.all_kwargs:
            setattr(self, kwarg_name, kwargs.get(kwarg_name))

        # If the scopes look like this:
        #
        #     'openid,fence,data'
        #
        # convert them to this:
        #
        #     ['openid', 'fence', 'data']
        if isinstance(getattr(self, "scopes", ""), str):
            self.scopes = [scope.strip() for scope in self.scopes.split(",")]

        self.expires_in = kwargs.get("expires_in") or self.default_expiration

    def create_access_token(self):
        """
        Create a new access token.

        Return:
            JWTResult: result containing the encoded token and claims
        """
        driver = get_SQLAlchemyDriver(self.db)
        with driver.session as current_session:
            user = query_for_user(session=current_session, username=self.username)

            if not user:
                raise EnvironmentError(
                    "no user found with given username: " + self.username
                )
            return generate_signed_access_token(
                self.kid,
                self.private_key,
                self.expires_in,
                self.scopes,
                user=user,
                iss=self.base_url,
            )

    def create_refresh_token(self):
        """
        Create a new refresh token and add its entry to the database.

        Return:
            JWTResult: the refresh token result
        """
        driver = get_SQLAlchemyDriver(self.db)
        with driver.session as current_session:
            user = query_for_user(session=current_session, username=self.username)

            if not user:
                raise EnvironmentError(
                    "no user found with given username: " + self.username
                )
            if not self.client_id:
                raise EnvironmentError(
                    "no client id is provided. Required for creating refresh token"
                )
            jwt_result = generate_signed_refresh_token(
                self.kid,
                self.private_key,
                user,
                self.expires_in,
                self.scopes,
                iss=self.base_url,
                client_id=self.client_id,
            )

            current_session.add(
                UserRefreshToken(
                    jti=jwt_result.claims["jti"],
                    userid=user.id,
                    expires=jwt_result.claims["exp"],
                )
            )

            return jwt_result


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
    driver = get_SQLAlchemyDriver(db)
    with driver.session as current_session:
        cloud_provider = (
            current_session.query(CloudProvider).filter_by(name=bucket_provider).first()
        )
        if not cloud_provider:
            raise NameError(
                'No bucket with provider "{}" exists.'.format(bucket_provider)
            )

        # first try by searching using id
        try:
            bucket_id = int(bucket_id)
            bucket_db_entry = (
                current_session.query(Bucket).filter_by(
                    id=bucket_id, provider_id=cloud_provider.id
                )
            ).first()
        except ValueError:
            # invalid id, must be int
            bucket_db_entry = None

        # nothing found? try searching for single bucket with name bucket_id
        if not bucket_db_entry:
            buckets_by_name = current_session.query(Bucket).filter_by(
                name=bucket_id, provider_id=cloud_provider.id
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
                    "buckets. Please specify the id from the db and not just "
                    "the name.".format(bucket_id=bucket_id)
                )
            else:
                # keep bucket_db_entry as None
                pass

        if not bucket_db_entry:
            raise NameError('No bucket with id or name "{}" exists.'.format(bucket_id))

        project_db_entry = (
            current_session.query(Project).filter_by(auth_id=project_auth_id).first()
        )
        if not project_db_entry:
            logger.warning(
                'WARNING: No project with auth_id "{}" exists. Creating...'.format(
                    project_auth_id
                )
            )
            project_db_entry = Project(name=project_auth_id, auth_id=project_auth_id)
            current_session.add(project_db_entry)
            current_session.commit()

        # Add StorageAccess if it doesn't exist for the project
        storage_access = (
            current_session.query(StorageAccess)
            .filter_by(project_id=project_db_entry.id, provider_id=cloud_provider.id)
            .first()
        )
        if not storage_access:
            storage_access = StorageAccess(
                project_id=project_db_entry.id, provider_id=cloud_provider.id
            )
            current_session.add(storage_access)
            current_session.commit()

        project_linkage = (
            current_session.query(ProjectToBucket)
            .filter_by(project_id=project_db_entry.id, bucket_id=bucket_db_entry.id)
            .first()
        )
        if not project_linkage:
            project_linkage = ProjectToBucket(
                project_id=project_db_entry.id,
                bucket_id=bucket_db_entry.id,
                privilege=["owner"],  # TODO What should this be???
            )
            current_session.add(project_linkage)
            current_session.commit()


def create_or_update_google_bucket(
    db,
    name,
    storage_class=None,
    public=None,
    requester_pays=False,
    google_project_id=None,
    project_auth_id=None,
    access_logs_bucket=None,
    allowed_privileges=None,
):
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
        public (bool or None, optional): whether or not the bucket should be public.
            None means leave IAM on the bucket unchanged.
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
    cirrus_config.update(**config["CIRRUS_CFG"])

    google_project_id = google_project_id or cirrus_config.GOOGLE_PROJECT_ID

    # determine project where buckets are located
    # default to same project, try to get storage creds project from key file
    storage_creds_project_id = _get_storage_project_id() or google_project_id

    # default to read access
    allowed_privileges = allowed_privileges or ["read", "write"]

    driver = get_SQLAlchemyDriver(db)
    with driver.session as current_session:
        # use storage creds to create bucket
        # (default creds don't have permission)
        bucket_db_entry = _create_or_update_google_bucket_and_db(
            db_session=current_session,
            name=name,
            storage_class=storage_class,
            requester_pays=requester_pays,
            storage_creds_project_id=storage_creds_project_id,
            public=public,
            project_auth_id=project_auth_id,
            access_logs_bucket=access_logs_bucket,
        )

        if public is not None and not public:
            for privilege in allowed_privileges:
                _setup_google_bucket_access_group(
                    db_session=current_session,
                    google_bucket_name=name,
                    bucket_db_id=bucket_db_entry.id,
                    google_project_id=google_project_id,
                    storage_creds_project_id=storage_creds_project_id,
                    privileges=[privilege],
                )


def create_google_logging_bucket(name, storage_class=None, google_project_id=None):
    cirrus_config.update(**config["CIRRUS_CFG"])

    # determine project where buckets are located if not provided, default
    # to configured project if checking creds doesn't work
    storage_creds_project_id = (
        google_project_id
        or _get_storage_project_id()
        or cirrus_config.GOOGLE_PROJECT_ID
    )

    manager = GoogleCloudManager(
        storage_creds_project_id, creds=cirrus_config.configs["GOOGLE_STORAGE_CREDS"]
    )
    with manager as g_mgr:
        g_mgr.create_or_update_bucket(
            name,
            storage_class=storage_class,
            public=False,
            requester_pays=False,
            for_logging=True,
        )

        logger.info(
            "Successfully created Google Bucket {} "
            "to store Access Logs.".format(name)
        )


def _get_storage_project_id():
    """
    Determine project where buckets are located.
    Try to get storage creds project from key file
    """
    storage_creds_project_id = None
    storage_creds_file = cirrus_config.configs["GOOGLE_STORAGE_CREDS"]
    if os.path.exists(storage_creds_file):
        with open(storage_creds_file) as creds_file:
            storage_creds_project_id = json.load(creds_file).get("project_id")
    return storage_creds_project_id


def _create_or_update_google_bucket_and_db(
    db_session,
    name,
    storage_class,
    public,
    requester_pays,
    storage_creds_project_id,
    project_auth_id,
    access_logs_bucket,
):
    """
    Handles creates the Google bucket and adding necessary db entry
    """
    manager = GoogleCloudManager(
        storage_creds_project_id, creds=cirrus_config.configs["GOOGLE_STORAGE_CREDS"]
    )
    with manager as g_mgr:
        g_mgr.create_or_update_bucket(
            name,
            storage_class=storage_class,
            public=public,
            requester_pays=requester_pays,
            access_logs_bucket=access_logs_bucket,
        )

        # add bucket to db
        google_cloud_provider = _get_or_create_google_provider(db_session)

        bucket_db_entry = (
            db_session.query(Bucket)
            .filter_by(name=name, provider_id=google_cloud_provider.id)
            .first()
        )
        if not bucket_db_entry:
            bucket_db_entry = Bucket(name=name, provider_id=google_cloud_provider.id)
            db_session.add(bucket_db_entry)
            db_session.commit()

        logger.info("Successfully updated Google Bucket {}.".format(name))

        # optionally link this new bucket to an existing project
        if project_auth_id:
            project_db_entry = (
                db_session.query(Project).filter_by(auth_id=project_auth_id).first()
            )
            if not project_db_entry:
                logger.info(
                    "No project with auth_id {} found. No linking "
                    "occured.".format(project_auth_id)
                )
            else:
                project_linkage = (
                    db_session.query(ProjectToBucket)
                    .filter_by(
                        project_id=project_db_entry.id, bucket_id=bucket_db_entry.id
                    )
                    .first()
                )
                if not project_linkage:
                    project_linkage = ProjectToBucket(
                        project_id=project_db_entry.id,
                        bucket_id=bucket_db_entry.id,
                        privilege=["owner"],  # TODO What should this be???
                    )
                    db_session.add(project_linkage)
                    db_session.commit()
                logger.info(
                    "Successfully linked project with auth_id {} "
                    "to the bucket.".format(project_auth_id)
                )

                # Add StorageAccess if it doesn't exist for the project
                storage_access = (
                    db_session.query(StorageAccess)
                    .filter_by(
                        project_id=project_db_entry.id,
                        provider_id=google_cloud_provider.id,
                    )
                    .first()
                )
                if not storage_access:
                    storage_access = StorageAccess(
                        project_id=project_db_entry.id,
                        provider_id=google_cloud_provider.id,
                    )
                    db_session.add(storage_access)
                    db_session.commit()

    return bucket_db_entry


def _setup_google_bucket_access_group(
    db_session,
    google_bucket_name,
    bucket_db_id,
    google_project_id,
    storage_creds_project_id,
    privileges,
):
    access_group = _create_google_bucket_access_group(
        db_session, google_bucket_name, bucket_db_id, google_project_id, privileges
    )
    # use storage creds to update bucket iam
    storage_manager = GoogleCloudManager(
        storage_creds_project_id, creds=cirrus_config.configs["GOOGLE_STORAGE_CREDS"]
    )
    with storage_manager as g_mgr:
        g_mgr.give_group_access_to_bucket(
            access_group.email, google_bucket_name, access=privileges
        )

    logger.info(
        "Successfully set up Google Bucket Access Group {} "
        "for Google Bucket {}.".format(access_group.email, google_bucket_name)
    )

    return access_group


def _create_google_bucket_access_group(
    db_session, google_bucket_name, bucket_db_id, google_project_id, privileges
):
    access_group = None
    prefix = config.get("GOOGLE_GROUP_PREFIX", "")
    # use default creds for creating group and iam policies
    with GoogleCloudManager(google_project_id) as g_mgr:
        # create bucket access group
        result = g_mgr.create_group(
            name=prefix
            + "_"
            + google_bucket_name
            + "_"
            + "_".join(privileges)
            + "_gbag"
        )
        group_email = result["email"]

        # add bucket group to db
        access_group = (
            db_session.query(GoogleBucketAccessGroup)
            .filter_by(bucket_id=bucket_db_id, email=group_email)
            .first()
        )
        if not access_group:
            access_group = GoogleBucketAccessGroup(
                bucket_id=bucket_db_id, email=group_email, privileges=privileges
            )
            db_session.add(access_group)
            db_session.commit()

    return access_group


def _get_or_create_google_provider(db_session):
    google_cloud_provider = (
        db_session.query(CloudProvider).filter_by(name="google").first()
    )
    if not google_cloud_provider:
        google_cloud_provider = CloudProvider(
            name="google", description="Google Cloud Platform", service="general"
        )
        db_session.add(google_cloud_provider)
        db_session.commit()
    return google_cloud_provider


def link_external_bucket(db, name):
    """
    Link with bucket owned by an external party. This will create the bucket
    in fence database and create a google group to access the bucket in both
    Google and fence database.
    The external party will need to add the google group read access to bucket
    afterwards.
    """

    cirrus_config.update(**config["CIRRUS_CFG"])

    google_project_id = cirrus_config.GOOGLE_PROJECT_ID

    db = get_SQLAlchemyDriver(db)
    with db.session as current_session:
        google_cloud_provider = _get_or_create_google_provider(current_session)

        # search for existing bucket based on name, try to use existing group email
        existing_bucket = current_session.query(Bucket).filter_by(name=name).first()
        if existing_bucket:
            access_group = (
                current_session.query(GoogleBucketAccessGroup)
                .filter(GoogleBucketAccessGroup.privileges.any("read"))
                .filter_by(bucket_id=existing_bucket.id)
                .all()
            )
            if len(access_group) > 1:
                raise Exception(
                    f"Existing bucket {name} has more than 1 associated "
                    "Google Bucket Access Group with privilege of 'read'. "
                    "This is not expected and we cannot continue linking."
                )
            elif len(access_group) == 0:
                raise Exception(
                    f"Existing bucket {name} has no associated "
                    "Google Bucket Access Group with privilege of 'read'. "
                    "This is not expected and we cannot continue linking."
                )

            access_group = access_group[0]

            email = access_group.email

            logger.warning(
                f"bucket already exists with name: {name}, using existing group email: {email}"
            )

            return email

        bucket_db_entry = Bucket(name=name, provider_id=google_cloud_provider.id)
        current_session.add(bucket_db_entry)
        current_session.commit()
        privileges = ["read"]

        access_group = _create_google_bucket_access_group(
            current_session,
            name,
            bucket_db_entry.id,
            google_project_id,
            privileges,
        )

    logger.info("bucket access group email: {}".format(access_group.email))
    return access_group.email


def verify_user_registration(DB):
    """
    Validate user registration
    """
    cirrus_config.update(**config["CIRRUS_CFG"])

    validation_check(DB)


def force_update_google_link(DB, username, google_email, expires_in=None):
    """
    WARNING: This function circumvents Google Auth flow, and should only be
    used for internal testing!
    WARNING: This function assumes that a user already has a proxy group!

    Adds user's google account to proxy group and/or updates expiration for
    that google account's access.
    WARNING: This assumes that provided arguments represent valid information.
             This BLINDLY adds without verification. Do verification
             before this.
    Specifically, this ASSUMES that the proxy group provided belongs to the
    given user and that the user has ALREADY authenticated to prove the
    provided google_email is also their's.

    Args:
        DB
        username (str): Username to link with
        google_email (str): Google email to link to

    Raises:
        NotFound: Linked Google account not found
        Unauthorized: Couldn't determine user

    Returns:
        Expiration time of the newly updated google account's access
    """
    cirrus_config.update(**config["CIRRUS_CFG"])

    db = get_SQLAlchemyDriver(DB)
    with db.session as session:
        user_account = query_for_user(session=session, username=username)

        if user_account:
            user_id = user_account.id
            proxy_group_id = user_account.google_proxy_group_id
        else:
            raise Unauthorized(
                "Could not determine authed user "
                "from session. Unable to link Google account."
            )

        user_google_account = (
            session.query(UserGoogleAccount)
            .filter(UserGoogleAccount.email == google_email)
            .first()
        )
        if not user_google_account:
            user_google_account = add_new_user_google_account(
                user_id, google_email, session
            )

        # time until the SA will lose bucket access
        # by default: use configured time or 7 days
        default_expires_in = config.get(
            "GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN", 604800
        )
        # use expires_in from arg if it was provided and it was not greater than the default
        expires_in = get_valid_expiration(
            expires_in, max_limit=default_expires_in, default=default_expires_in
        )
        # convert expires_in to timestamp
        expiration = int(time.time() + expires_in)

        force_update_user_google_account_expiration(
            user_google_account, proxy_group_id, google_email, expiration, session
        )

        session.commit()

        return expiration


def notify_problem_users(db, emails, auth_ids, check_linking, google_project_id):
    """
    Builds a list of users (from provided list of emails) who do not
    have access to any subset of provided auth_ids. Send email to users
    informing them to get access to needed projects.

    db (string): database instance
    emails (list(string)): list of emails to check for access
    auth_ids (list(string)): list of project auth_ids to check that emails have access
    check_linking (bool): flag for if emails should be checked for linked google email
    """
    email_users_without_access(db, auth_ids, emails, check_linking, google_project_id)


def migrate_database():
    alembic_main(["--raiseerr", "upgrade", "head"])
    logger.info("Done.")


def google_list_authz_groups(db):
    """
    Builds a list of Google authorization information which includes
    the Google Bucket Access Group emails, Bucket(s) they're associated with, and
    underlying Fence Project auth_id that provides access to that Bucket/Group

    db (string): database instance
    """
    driver = get_SQLAlchemyDriver(db)

    with driver.session as db_session:
        google_authz = (
            db_session.query(
                GoogleBucketAccessGroup.email,
                Bucket.name,
                Project.auth_id,
                ProjectToBucket,
            )
            .join(Project, ProjectToBucket.project_id == Project.id)
            .join(Bucket, ProjectToBucket.bucket_id == Bucket.id)
            .join(
                GoogleBucketAccessGroup, GoogleBucketAccessGroup.bucket_id == Bucket.id
            )
        ).all()

        print("GoogleBucketAccessGroup.email, Bucket.name, Project.auth_id")
        for item in google_authz:
            print(", ".join(item[:-1]))

        return google_authz


def access_token_polling_job(
    db, chunk_size=None, concurrency=None, thread_pool_size=None, buffer_size=None
):
    """
    Update visas and refresh tokens for users with valid visas and refresh tokens

    db (string): database instance
    chunk_size (int): size of chunk of users we want to take from each iteration
    concurrency (int): number of concurrent users going through the visa update flow
    thread_pool_size (int): number of Docker container CPU used for jwt verifcation
    buffer_size (int): max size of queue
    """
    # Instantiating a new client here because the existing
    # client uses authz_provider
    arborist = ArboristClient(
        arborist_base_url=config["ARBORIST"],
        logger=get_logger("user_syncer.arborist_client"),
    )
    driver = get_SQLAlchemyDriver(db)
    job = TokenAndAuthUpdater(
        chunk_size=int(chunk_size) if chunk_size else None,
        concurrency=int(concurrency) if concurrency else None,
        thread_pool_size=int(thread_pool_size) if thread_pool_size else None,
        buffer_size=int(buffer_size) if buffer_size else None,
        arborist=arborist,
    )
    with driver.session as db_session:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(job.update_tokens(db_session))
