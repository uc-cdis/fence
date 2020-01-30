import time
import json
import os
from cryptography.fernet import Fernet
import flask
from flask_sqlalchemy_session import current_session
from sqlalchemy import desc, func

from cdislogging import get_logger
from cirrus import GoogleCloudManager
from cirrus.google_cloud.iam import GooglePolicyMember
from cirrus.google_cloud.utils import (
    get_valid_service_account_id_for_client,
    get_valid_service_account_id_for_user,
)

from userdatamodel.driver import SQLAlchemyDriver
from userdatamodel.user import GoogleProxyGroup, User, AccessPrivilege

from fence.auth import current_token
from fence.config import config
from fence.errors import NotSupported, InternalError, UserError
from fence.models import (
    GoogleServiceAccount,
    GoogleServiceAccountKey,
    UserGoogleAccount,
    UserGoogleAccountToProxyGroup,
    UserServiceAccount,
    ServiceAccountAccessPrivilege,
    ServiceAccountToGoogleBucketAccessGroup,
)
from fence.resources.google import STORAGE_ACCESS_PROVIDER_NAME
from fence.errors import NotSupported, NotFound

from cdislogging import get_logger

logger = get_logger(__name__)


def get_or_create_primary_service_account_key(
    user_id, username, proxy_group_id, expires=None
):
    """
    Get or create a key for the user's primary service account in their
    proxy group.

    If a key is not stored in the db this will create a new one with
    the provided expiration (or use the default).

    NOTE: This will create a primary service account for the user if one does
          not exist (so that a key can be generated).

    WARNING: If the service account key already exists, the `expires` param
             given will be ignored.

    Args:
        user_id (str): user identifier
        proxy_group_id (str): user's google proxy group identifier
        expires (int, optional): unix time to expire the newly created SA key
            (only used if a new key is required!)

    Returns:
        dict: JSON Google Credentials

    Raises:
        InternalError: User doesn't have a primary service account
    """
    sa_private_key = {}
    user_service_account_key = _get_primary_service_account_key(
        user_id, username, proxy_group_id
    )

    if user_service_account_key:
        fernet_key = Fernet(str(config["ENCRYPTION_KEY"]))
        private_key_bytes = fernet_key.decrypt(
            bytes(user_service_account_key.private_key, "utf-8")
        )
        sa_private_key = json.loads(private_key_bytes.decode("utf-8"))
    else:
        sa_private_key = create_primary_service_account_key(
            user_id, username, proxy_group_id, expires
        )

    return sa_private_key, user_service_account_key


def _get_primary_service_account_key(user_id, username, proxy_group_id):
    user_service_account_key = None

    # Note that client_id is None, which is how we store the user's SA
    user_google_service_account = get_service_account(client_id=None, user_id=user_id)

    if user_google_service_account:
        user_service_account_key = (
            current_session.query(GoogleServiceAccountKey)
            .filter(
                GoogleServiceAccountKey.service_account_id
                == user_google_service_account.id
            )
            .filter(GoogleServiceAccountKey.private_key.isnot(None))
            .order_by(desc(GoogleServiceAccountKey.expires))
            .first()
        )

    return user_service_account_key


def create_primary_service_account_key(user_id, username, proxy_group_id, expires=None):
    """
    Return an access key for current user.

    NOTE: This will create a service account for the client if one does
    not exist.

    Returns:

        JSON key in Google Credentials File format:

        .. code-block:: JavaScript

            {
                "type": "service_account",
                "project_id": "project-id",
                "private_key_id": "some_number",
                "private_key": "-----BEGIN PRIVATE KEY-----\n....
                =\n-----END PRIVATE KEY-----\n",
                "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
                "client_id": "...",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com"
            }
    """
    # Note that client_id is None, which is how we store the user's SA
    sa_private_key, service_account = create_google_access_key(
        None, user_id, username, proxy_group_id
    )

    key_id = sa_private_key.get("private_key_id")

    fernet_key = Fernet(str(config["ENCRYPTION_KEY"]))
    private_key_bytes = json.dumps(sa_private_key).encode("utf-8")
    private_key = fernet_key.encrypt(private_key_bytes).decode("utf-8")

    expires = expires or (
        int(time.time())
        + config["GOOGLE_SERVICE_ACCOUNT_KEY_FOR_URL_SIGNING_EXPIRES_IN"]
    )

    add_custom_service_account_key_expiration(
        key_id, service_account.id, expires, private_key=private_key
    )

    return sa_private_key


def give_service_account_billing_access_if_necessary(
    sa_private_key, r_pays_project=None, default_billing_project=None
):
    """
    Give the Service Account (whose key is provided) the privilege to bill to the
    given project. If a project is not provided and there is a configured Google project
    to bill to, we will use that.

    Args:
        sa_private_key (dict): JSON key in Google Credentials File format:

            .. code-block:: JavaScript

                {
                    "type": "service_account",
                    "project_id": "project-id",
                    "private_key_id": "some_number",
                    "private_key": "-----BEGIN PRIVATE KEY-----\n....
                    =\n-----END PRIVATE KEY-----\n",
                    "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
                    "client_id": "...",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://accounts.google.com/o/oauth2/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com"
                }
        r_pays_project (str, optional): The Google Project identifier to bill to
        default_billing_project (str, optional): the default The Google Project
            identifier to bill to if r_pays_project is None
    """
    if not r_pays_project and not default_billing_project:
        sa_account_id = sa_private_key.get("client_email")
        raise UserError(
            "You did NOT provide a `userProject` for requester pays billing, "
            "so we could not create a custom role in that project to provide "
            "the necessary service account ({}) billing permission. "
            "Our main service account ({}) will need valid permissions in the "
            "project you supplied to create a custom role and change the project "
            "IAM policy. There is no configured default billing project so you must "
            "provide a `userProject` query parameter.".format(
                sa_account_id, config["CIRRUS_CFG"].get("GOOGLE_ADMIN_EMAIL")
            )
        )

    # use configured project if it exists and no user project was given
    is_default_billing = False
    if default_billing_project and not r_pays_project:
        r_pays_project = default_billing_project
        is_default_billing = True

    if r_pays_project:
        sa_account_id = sa_private_key.get("client_email")

        try:
            # attempt to create custom role that gives
            # the SA access to bill the project provided
            # NOTE: this may fail if our fence SA doesn't have the right permissions
            #       to add this role and update the project policy
            with GoogleCloudManager(project_id=r_pays_project) as g_cloud_manager:
                g_cloud_manager.give_service_account_billing_access(
                    sa_account_id, project_id=r_pays_project
                )
        except Exception as exc:
            logger.error(
                "Unable to create a custom role in Google Project {} to "
                "give Google service account {} rights to bill the project. Error: {}".format(
                    r_pays_project, sa_account_id, exc
                )
            )
            if is_default_billing:
                raise InternalError(
                    "Fence has a configured Google Project for requester pays billing ({}), "
                    "but could not create a custom role in that project to provide "
                    "the necessary service account ({}) billing permission. It could be that "
                    "the Fence admin service account ({}) does not have valid permissions in the "
                    "project.".format(
                        r_pays_project,
                        sa_account_id,
                        config["CIRRUS_CFG"].get("GOOGLE_ADMIN_EMAIL"),
                    )
                )
            else:
                raise NotSupported(
                    "You provided {} as a `userProject` for requester pays billing, "
                    "but we could not create a custom role in that project to provide "
                    "the necessary service account ({}) billing permission. It could be that "
                    "our main service account ({}) does not have valid permissions in the "
                    "project you supplied to create a custom role and change the project IAM policy.".format(
                        r_pays_project,
                        sa_account_id,
                        config["CIRRUS_CFG"].get("GOOGLE_ADMIN_EMAIL"),
                    )
                )

        logger.info(
            "Created a custom role in Google Project {} to "
            "give Google service account {} rights to bill the project.".format(
                r_pays_project, sa_account_id
            )
        )


def create_google_access_key(client_id, user_id, username, proxy_group_id):
    """
    Return an access key for current user and client.

    NOTE: This will create a service account for the client if one does
    not exist.

    Returns:

        JSON key in Google Credentials File format:

        .. code-block:: JavaScript

            {
                "type": "service_account",
                "project_id": "project-id",
                "private_key_id": "some_number",
                "private_key": "-----BEGIN PRIVATE KEY-----\n....
                =\n-----END PRIVATE KEY-----\n",
                "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
                "client_id": "...",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com"
            }
    """
    key = {}
    service_account = get_or_create_service_account(
        client_id=client_id,
        user_id=user_id,
        username=username,
        proxy_group_id=proxy_group_id,
    )

    with GoogleCloudManager() as g_cloud:
        key = g_cloud.get_access_key(service_account.email)

    logger.info(
        "Created key with id {} for service account {} in user {}'s "
        "proxy group {} (user's id: {}).".format(
            key.get("private_key_id"),
            service_account.email,
            username,
            proxy_group_id,
            user_id,
        )
    )

    return key, service_account


def _get_linked_google_account(user_id, db=None):
    """
    Hit db to check for linked google account of user
    """
    session = get_db_session(db)

    g_account = (
        session.query(UserGoogleAccount)
        .filter(UserGoogleAccount.user_id == user_id)
        .first()
    )
    return g_account


def get_linked_google_account_email(user_id, db=None):
    """
    Hit db to check for linked google account email of user
    """
    google_email = None
    if user_id:
        g_account = _get_linked_google_account(user_id, db=db)
        if g_account:
            google_email = g_account.email
    return google_email


def get_linked_google_account_exp(user_id, db=None):
    """
    Hit db to check for expiration of linked google account of user
    """
    session = get_db_session(db)

    google_account_exp = 0
    if user_id:
        g_account = _get_linked_google_account(user_id, db=db)
        if g_account:
            g_account_to_proxy_group = (
                session.query(UserGoogleAccountToProxyGroup)
                .filter(
                    UserGoogleAccountToProxyGroup.user_google_account_id == g_account.id
                )
                .first()
            )
            if g_account_to_proxy_group:
                google_account_exp = g_account_to_proxy_group.expires
    return google_account_exp


def add_custom_service_account_key_expiration(
    key_id, service_account_id, expires, private_key=None
):
    """
    Add db entry of user service account key and its custom expiration.
    """
    sa_key = GoogleServiceAccountKey(
        key_id=key_id,
        service_account_id=service_account_id,
        expires=expires,
        private_key=private_key,
    )
    current_session.add(sa_key)
    current_session.commit()


def get_service_account(client_id, user_id):
    """
    Return the service account (from Fence db) for given client.

    Get the service account that is associated with the given client
    for this user. There will be a single service account per client.

    NOTE: The user themselves have a "primary" service account which you
          can retrieve by passing in `None` as the client_id.

    Returns:
        fence.models.GoogleServiceAccount: Client's service account
    """
    service_account = (
        current_session.query(GoogleServiceAccount)
        .filter_by(client_id=client_id, user_id=user_id)
        .first()
    )

    return service_account


def get_or_create_service_account(client_id, user_id, username, proxy_group_id):
    """
    Create a Google Service account for the current client and user.
    This effectively handles conflicts in Google and will update our db
    accordingly based on the newest information from Google.

    Args:
        g_cloud_manager (cirrus.GoogleCloudManager): instance of
        cloud manager to use

    Returns:
        fence.models.GoogleServiceAccount: New service account
    """
    if proxy_group_id:
        if client_id:
            service_account_id = get_valid_service_account_id_for_client(
                client_id, user_id, prefix=config["GOOGLE_SERVICE_ACCOUNT_PREFIX"]
            )
        else:
            service_account_id = get_valid_service_account_id_for_user(
                user_id, username, prefix=config["GOOGLE_SERVICE_ACCOUNT_PREFIX"]
            )

        with GoogleCloudManager() as g_cloud:
            new_service_account = g_cloud.create_service_account_for_proxy_group(
                proxy_group_id, account_id=service_account_id
            )

        return _update_service_account_db_entry(
            client_id, user_id, proxy_group_id, new_service_account
        )
    else:
        flask.abort(
            404,
            "Could not find Google proxy group for current user in the given token.",
        )


def _update_service_account_db_entry(
    client_id, user_id, proxy_group_id, new_service_account
):
    """
    Now that SA exists in Google so lets check our db and update/add as necessary
    """

    # if we're now using a prefix for SAs, cleanup the db
    if config["GOOGLE_SERVICE_ACCOUNT_PREFIX"]:
        # - if using the old naming convention without a prefix,
        # remove that SA from the db b/c we'll be using the new one from now on
        # - construct old email using account id provided and
        # domain from new email to find the db entry
        old_service_account_id = get_valid_service_account_id_for_client(
            client_id, user_id
        )
        old_sa_email = "@".join(
            (old_service_account_id, new_service_account["email"].split("@")[-1])
        )

        # clear out old SA and keys if there is one
        old_service_account_db_entry = (
            current_session.query(GoogleServiceAccount)
            .filter(GoogleServiceAccount.email == old_sa_email)
            .first()
        )
        if old_service_account_db_entry:
            logger.info(
                "Found Google Service Account using old naming convention without a prefix: "
                "{}. Removing from db. Keys should still have access in Google until "
                "cronjob removes them (e.g. fence-create google-manage-keys). NOTE: "
                "the SA will still exist in Google but fence will use new SA {} for "
                "new keys.".format(old_sa_email, new_service_account["email"])
            )

            old_service_account_keys_db_entries = (
                current_session.query(GoogleServiceAccountKey)
                .filter(
                    GoogleServiceAccountKey.service_account_id
                    == old_service_account_db_entry.id
                )
                .all()
            )

            # remove the keys then the sa itself from db
            for old_key in old_service_account_keys_db_entries:
                current_session.delete(old_key)

            current_session.commit()
            current_session.delete(old_service_account_db_entry)

    service_account_db_entry = (
        current_session.query(GoogleServiceAccount)
        .filter(GoogleServiceAccount.email == new_service_account["email"])
        .first()
    )

    if not service_account_db_entry:
        service_account_db_entry = GoogleServiceAccount(
            google_unique_id=new_service_account["uniqueId"],
            client_id=client_id,
            user_id=user_id,
            email=new_service_account["email"],
            google_project_id=new_service_account["projectId"],
        )
        current_session.add(service_account_db_entry)
    else:
        service_account_db_entry.google_unique_id = new_service_account["uniqueId"]
        service_account_db_entry.email = new_service_account["email"]
        service_account_db_entry.google_project_id = (new_service_account["projectId"],)

    current_session.commit()

    logger.info(
        "Created service account {} for proxy group {}.".format(
            new_service_account["email"], proxy_group_id
        )
    )

    return service_account_db_entry


def get_or_create_proxy_group_id():
    """
    If no username returned from token or database, create a new proxy group
    for the give user. Also, add the access privileges.

    Returns:
        int: id of (possibly newly created) proxy group associated with user
    """
    proxy_group_id = _get_proxy_group_id()
    if not proxy_group_id:
        user_id = current_token["sub"]
        username = current_token.get("context", {}).get("user", {}).get("name", "")
        proxy_group_id = _create_proxy_group(user_id, username).id

        privileges = current_session.query(AccessPrivilege).filter(
            AccessPrivilege.user_id == user_id
        )

        for p in privileges:
            storage_accesses = p.project.storage_access

            for sa in storage_accesses:
                if sa.provider.name == STORAGE_ACCESS_PROVIDER_NAME:

                    flask.current_app.storage_manager.logger.info(
                        "grant {} access {} to {} in {}".format(
                            username, p.privilege, p.project_id, p.auth_provider
                        )
                    )

                    flask.current_app.storage_manager.grant_access(
                        provider=(sa.provider.name),
                        username=username,
                        project=p.project,
                        access=p.privilege,
                        session=current_session,
                    )

    return proxy_group_id


def _get_proxy_group_id():
    """
    Get users proxy group id from the current token, if possible.
    Otherwise, check the database for it.

    Returnns:
        int: id of proxy group associated with user
    """
    proxy_group_id = get_users_proxy_group_from_token()

    if not proxy_group_id:
        user = (
            current_session.query(User).filter(User.id == current_token["sub"]).first()
        )
        proxy_group_id = user.google_proxy_group_id

    return proxy_group_id


def _create_proxy_group(user_id, username):
    """
    Create a proxy group for the given user

    Args:
        user_id (int): unique integer id for user
        username (str): unique name for user

    Return:
        userdatamodel.user.GoogleProxyGroup: the newly created proxy group
    """

    with GoogleCloudManager() as g_cloud:
        prefix = get_prefix_for_google_proxy_groups()
        new_proxy_group = g_cloud.create_proxy_group_for_user(
            user_id, username, prefix=prefix
        )

    proxy_group = GoogleProxyGroup(
        id=new_proxy_group["id"], email=new_proxy_group["email"]
    )

    # link proxy group to user
    user = current_session.query(User).filter_by(id=user_id).first()
    user.google_proxy_group_id = proxy_group.id

    current_session.add(proxy_group)
    current_session.commit()

    logger.info(
        "Created proxy group {} for user {} with id {}.".format(
            new_proxy_group["email"], username, user_id
        )
    )

    return proxy_group


def get_default_google_account_expiration():
    now = int(time.time())
    expiration = now + config["GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN"]
    return expiration


def get_users_linked_google_email(user_id):
    """
    Return user's linked google account's email.
    """
    google_email = get_users_linked_google_email_from_token()
    if not google_email:
        # hit db to check for google_email if it's not in token.
        # this will catch cases where the linking happened during the life
        # of an access token and the same access token is used here (e.g.
        # account exists but a new token hasn't been generated with the linkage
        # info yet)
        google_email = get_linked_google_account_email(user_id)
    return google_email


def get_users_linked_google_email_from_token():
    """
    Return a user's linked Google Account's email address by parsing the
    JWT token in the header.

    Returns:
        str: email address of account or None
    """
    if current_token:
        return (
            current_token.get("context", {})
            .get("user", {})
            .get("google", {})
            .get("linked_google_account", None)
        )

    return None


def get_users_proxy_group_from_token():
    """
    Return a user's proxy group ID by parsing the
    JWT token in the header.

    Returns:
        str: proxy group ID or None
    """
    if current_token:
        return (
            current_token.get("context", {})
            .get("user", {})
            .get("google", {})
            .get("proxy_group", None)
        )

    return None


def get_prefix_for_google_proxy_groups():
    """
    Return a string prefix for Google proxy groups based on configuration.

    Returns:
        str: prefix for proxy groups
    """
    prefix = config.get("GOOGLE_GROUP_PREFIX")
    if not prefix:
        raise NotSupported(
            "GOOGLE_GROUP_PREFIX must be set in the configuration. "
            "This namespaces the Google groups for security and safety."
        )
    return prefix


def get_all_registered_service_accounts(db=None):
    """
    Get all registered service accounts from db
    """
    session = get_db_session(db)

    registered_service_accounts = (
        session.query(UserServiceAccount)
        .join(ServiceAccountToGoogleBucketAccessGroup)
        .filter(
            UserServiceAccount.id
            == ServiceAccountToGoogleBucketAccessGroup.service_account_id
        )
        .all()
    )

    return list(registered_service_accounts)


def get_registered_service_accounts_with_access(google_project_id, db=None):
    session = get_db_session(db)

    return (
        session.query(UserServiceAccount)
        .join(ServiceAccountToGoogleBucketAccessGroup)
        .filter(
            UserServiceAccount.id
            == ServiceAccountToGoogleBucketAccessGroup.service_account_id
        )
        .filter(UserServiceAccount.google_project_id == google_project_id)
        .all()
    )


def get_registered_service_accounts(google_project_id, db=None):
    session = get_db_session(db)

    return (
        session.query(UserServiceAccount)
        .filter_by(google_project_id=google_project_id)
        .all()
    )


def get_project_access_from_service_accounts(service_accounts, db=None):
    """
    Get a list of projects all the provided service accounts have
    access to. list will be of UserServiceAccount db objects

    Returns a list of Project objects
    """
    session = get_db_session(db)

    projects = []
    for service_account in service_accounts:
        access = [
            access_privilege.project
            for access_privilege in (
                session.query(ServiceAccountAccessPrivilege)
                .filter_by(service_account_id=service_account.id)
                .all()
            )
            if access_privilege.project is not None
        ]
        projects.extend(access)
    return list(projects)


def get_service_account_ids_from_google_members(members):
    """
    Get list of all service account ids given service account members on a
    google project

    Args:
        members(List[cirrus.google_cloud.iam.GooglePolicyMember]): Members on
            the google project who are of type User

    Return:
        list<str>: list of service account ids (emails)
    """
    return [
        member.email_id
        for member in members
        if member.member_type == GooglePolicyMember.SERVICE_ACCOUNT
    ]


def get_users_from_google_members(members, db=None):
    """
    Get User objects for all members on a Google project by checking db.

    Args:
        members(List[cirrus.google_cloud.iam.GooglePolicyMember]): Members on
            the google project who are of type User

    Return:
        List[fence.models.User]: Users from our db for members on Google project

    Raises:
        NotFound: Member on google project doesn't exist in our db
    """
    result = []
    for member in members:
        user = get_user_from_google_member(member, db=db)
        if user:
            result.append(user)
        else:
            raise NotFound(
                "Google member {} does not exist as a linked Google Account.".format(
                    member
                )
            )

    return result


def get_user_from_google_member(member, db=None):
    """
    Get User object for all members on a Google project by checking db.

    Args:
        member(cirrus.google_cloud.iam.GooglePolicyMember): Member on
            the google project who are of type User

    Return:
        fence.models.User: User from our db for member on Google project
    """
    session = get_db_session(db)

    linked_google_account = (
        session.query(UserGoogleAccount)
        .filter(func.lower(UserGoogleAccount.email) == member.email_id.lower().strip())
        .first()
    )
    if linked_google_account:
        return (
            session.query(User).filter(User.id == linked_google_account.user_id).first()
        )

    return None


def get_google_app_creds(app_creds_file=None):
    """
    Get the google app creds from the cirrus configuration.
    """
    app_creds_file = app_creds_file or config.get("CIRRUS_CFG", {}).get(
        "GOOGLE_APPLICATION_CREDENTIALS"
    )

    creds = None
    if app_creds_file and os.path.exists(app_creds_file):
        with open(app_creds_file) as app_creds_file:
            creds = json.load(app_creds_file)

    return creds


def get_monitoring_service_account_email(app_creds_file=None):
    """
    Get the monitoring email from the cirrus configuration. Use the
    main/default application credentials as the monitoring service account.

    This function should ONLY return the service account's email by
    parsing the creds file.
    """
    creds_email = None
    creds = get_google_app_creds(app_creds_file)
    if creds:
        creds_email = creds.get("client_email")

    return creds_email


def is_google_managed_service_account(service_account_email):
    """
    Return whether or not the given service account email represents a Google
    managed account (e.g. not user-created).
    """
    service_account_domain = "{}".format(service_account_email.split("@")[-1])

    google_managed_service_account_domains = config.get(
        "GOOGLE_MANAGED_SERVICE_ACCOUNT_DOMAINS", []
    )

    return service_account_domain in google_managed_service_account_domains


def get_db_session(db=None):
    if db:
        return SQLAlchemyDriver(db).Session()
    else:
        return current_session
