from cdislogging import get_logger
from cirrus import GoogleCloudManager
from cirrus.google_cloud.utils import get_proxy_group_name_for_user
from fence.config import config
from fence.errors import NotFound, UserError, UnavailableError
from fence.models import (
    GoogleProxyGroup,
    GoogleProxyGroupToGoogleBucketAccessGroup,
    GoogleServiceAccount,
    GoogleServiceAccountKey,
    User,
    UserGoogleAccount,
    UserGoogleAccountToProxyGroup,
    query_for_user,
)
from fence.resources import group as gp, project as pj, user as us, userdatamodel as udm
from flask import current_app as capp


__all__ = [
    "connect_user_to_project",
    "get_user_info",
    "get_all_users",
    "get_user_groups",
    "create_user",
    "update_user",
    "add_user_to_projects",
    "delete_user",
    "add_user_to_groups",
    "connect_user_to_group",
    "remove_user_from_groups",
    "disconnect_user_from_group",
    "remove_user_from_project",
]


logger = get_logger(__name__)


def connect_user_to_project(current_session, usr, project=None):
    """
    Create a user name for the specific project.
    Returns a dictionary.
    """
    datamodel_user = udm.create_user_by_username_project(current_session, usr, project)

    proj = datamodel_user["project"]
    priv = datamodel_user["privileges"]
    cloud_providers = udm.get_cloud_providers_from_project(current_session, proj.id)
    response = []
    for provider in cloud_providers:
        capp.storage_manager.get_or_create_user(provider.backend, usr)
        buckets = udm.get_buckets_by_project_cloud_provider(
            current_session, proj.id, provider.id
        )
        for bucket in buckets["buckets"]:
            try:
                capp.storage_manager.update_bucket_acl(
                    provider.backend, bucket, (usr, priv.privilege)
                )
                msg = "Success: user access" " created for a bucket in the project {0}"
                response.append(msg.format(proj.name))
            except:
                msg = "Error user access not" " created for project {0} and bucket {2}"
                response.append(msg.format(proj.name, bucket["name"]))
    return response


def get_user_info(current_session, username):
    return us.get_user_info(current_session, username)


def get_all_users(current_session):
    users = udm.get_all_users(current_session)
    users_names = []
    for user in users:
        new_user = {}
        new_user["name"] = user.username
        if user.is_admin:
            new_user["role"] = "admin"
        else:
            new_user["role"] = "user"
        users_names.append(new_user)
    return {"users": users_names}


def get_user_groups(current_session, username):
    user_groups = us.get_user_groups(current_session, username)["groups"]
    user_groups_info = []
    for group in user_groups:
        user_groups_info.append(gp.get_group_info(current_session, group))
    return {"groups": user_groups_info}


def create_user(current_session, username, role, email):
    """
    Create a user for all the projects or groups in the list.
    If the user already exists, to avoid unadvertedly changing it, we suggest update
    Returns a dictionary.
    """
    if not username:
        raise UserError(("Error: Please provide a username"))
    try:
        usr = us.get_user(current_session, username)
        raise UserError(
            (
                "Error: user already exist. If this is not a"
                " mistake, please, retry using update"
            )
        )
    except NotFound:
        user_list = [
            user["name"].upper() for user in get_all_users(current_session)["users"]
        ]
        if username.upper() in user_list:
            raise UserError(
                (
                    "Error: user with a name with the same combination/order "
                    "of characters already exists. Please remove this other user"
                    " or modify the new one. Contact us in case of doubt"
                )
            )
        is_admin = role == "admin"
        email_add = email
        usr = User(username=username, active=True, is_admin=is_admin, email=email_add)
        current_session.add(usr)
        return us.get_user_info(current_session, username)


def update_user(current_session, username, role, email, new_name):
    usr = us.get_user(current_session, username)
    user_list = [
        user["name"].upper() for user in get_all_users(current_session)["users"]
    ]
    if (
        new_name
        and new_name.upper() in user_list
        and not username.upper() == new_name.upper()
    ):
        raise UserError(
            (
                "Error: user with a name with the same combination/order "
                "of characters already exists. Please remove this other user"
                " or modify the new one. Contact us in case of doubt"
            )
        )
    usr.email = email or usr.email
    if role:
        usr.is_admin = role == "admin"
    usr.username = new_name or usr.username
    return us.get_user_info(current_session, usr.username)


def add_user_to_projects(current_session, username, projects=None):
    if not projects:
        projects = []
    usr = us.get_user(current_session, username)
    responses = []
    for proj in projects:
        try:
            response = connect_user_to_project(current_session, usr, proj)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    return {"result": responses}


def delete_google_service_accounts_and_keys(current_session, gcm, gpg_email):
    """
    Delete from both Google and Fence all Google service accounts and
    service account keys associated with one Google proxy group.
    """
    logger.debug("Deleting all associated service accounts...")

    # Referring to cirrus for list of SAs. You _could_ refer to fence db instead.
    service_account_emails = gcm.get_service_accounts_from_group(gpg_email)

    def raise_unavailable(sae):
        raise UnavailableError(
            "Error: Google unable to delete service account {}. Aborting".format(sae)
        )

    for sae in service_account_emails:
        # Upon deletion of a service account, Google will
        # automatically delete all key IDs associated with that
        # service account. So we skip doing that here.
        logger.debug(
            "Attempting to delete Google service account with email {} "
            "along with all associated service account keys...".format(sae)
        )
        try:
            r = gcm.delete_service_account(sae)
        except Exception as e:
            logger.exception(e)
            raise_unavailable(sae)

        if r != {}:
            logger.exception(r)
            raise_unavailable(sae)

        logger.info(
            "Google service account with email {} successfully removed "
            "from Google, along with all associated service account keys.".format(sae)
        )
        logger.debug(
            "Attempting to clear service account records from Fence database..."
        )
        sa = (
            current_session.query(GoogleServiceAccount)
            .filter(GoogleServiceAccount.email == sae)
            .first()
            # one_or_none() would be better, but is only in sqlalchemy 1.0.9
        )
        if sa:
            sa_keys = (
                current_session.query(GoogleServiceAccountKey)
                .filter(GoogleServiceAccountKey.service_account_id == sa.id)
                .all()
            )
            for sak in sa_keys:
                current_session.delete(sak)
            current_session.delete(sa)
            current_session.commit()
            logger.info(
                "Records for service account {} successfully cleared from Fence database.".format(
                    sae
                )
            )
        else:
            logger.info(
                "Records for service account {} NOT FOUND in Fence database. "
                "Continuing anyway.".format(sae)
            )


def delete_google_proxy_group(
    current_session, gcm, gpg_email, google_proxy_group_from_fence_db, user
):
    """
    Delete a Google proxy group from both Google and Fence.

    google_proxy_group_from_fence_db is the GPG row in Fence. If there is ever the case where
    the GPG exists in Google but is not in the Fence db, google_proxy_group_from_fence_db will be None
    but there will still be a GPG to delete from Google.

    user is the User row in Fence.
    """
    # Google will automatically remove
    # this proxy group from all GBAGs the proxy group is a member of.
    # So we skip doing that here.
    logger.debug(
        "Attempting to delete Google proxy group with email {}...".format(gpg_email)
    )

    def raise_unavailable(gpg_email):
        raise UnavailableError(
            "Error: Google unable to delete proxy group {}. Aborting".format(gpg_email)
        )

    try:
        r = gcm.delete_group(gpg_email)
    except Exception as e:
        logger.exception(e)
        raise_unavailable(gpg_email)

    if r != {}:
        logger.exception(r)
        raise_unavailable(gpg_email)

    logger.info(
        "Google proxy group with email {} successfully removed from Google.".format(
            gpg_email
        )
    )
    if google_proxy_group_from_fence_db:
        # (else it was google_proxy_group_from_google and there is nothing to delete in Fence db.)
        logger.debug("Attempting to clear proxy group records from Fence database...")
        logger.debug(
            "Deleting rows in {}...".format(
                GoogleProxyGroupToGoogleBucketAccessGroup.__tablename__
            )
        )
        gpg_to_gbag = (
            current_session.query(GoogleProxyGroupToGoogleBucketAccessGroup)
            .filter(
                GoogleProxyGroupToGoogleBucketAccessGroup.proxy_group_id
                == google_proxy_group_from_fence_db.id
            )
            .all()
        )
        for row in gpg_to_gbag:
            current_session.delete(row)
        logger.debug(
            "Deleting rows in {}...".format(UserGoogleAccountToProxyGroup.__tablename__)
        )
        uga_to_pg = (
            current_session.query(UserGoogleAccountToProxyGroup)
            .filter(
                UserGoogleAccountToProxyGroup.proxy_group_id
                == google_proxy_group_from_fence_db.id
            )
            .all()
        )
        for row in uga_to_pg:
            current_session.delete(row)
        logger.debug("Deleting rows in {}...".format(UserGoogleAccount.__tablename__))
        uga = (
            current_session.query(UserGoogleAccount)
            .filter(UserGoogleAccount.user_id == user.id)
            .all()
        )
        for row in uga:
            current_session.delete(row)
        logger.debug("Deleting row in {}...".format(GoogleProxyGroup.__tablename__))
        current_session.delete(google_proxy_group_from_fence_db)
        current_session.commit()
        logger.info(
            "Records for Google proxy group {} successfully cleared from Fence "
            "database, along with associated user Google accounts.".format(gpg_email)
        )
        logger.info("Done with Google deletions.")


def delete_user(current_session, username):
    """
    Remove a user from both the userdatamodel
    and the associated storage for that project/bucket.
    Returns a dictionary.

    The Fence db may not always be in perfect sync with Google.  We err on the
    side of safety (we prioritise making sure the user is really cleared out of
    Google to prevent unauthorized data access issues; we prefer cirrus/Google
    over the Fence db as the source of truth.) So, if the Fence-Google sync
    situation changes, do edit this code accordingly.
    """

    logger.debug("Beginning delete user.")

    with GoogleCloudManager() as gcm:
        # Delete user's service accounts, SA keys, user proxy group from Google.
        # Noop if Google not in use.

        user = query_for_user(session=current_session, username=username)
        if not user:
            raise NotFound("user name {} not found".format(username))

        logger.debug("Found user in Fence db: {}".format(user))

        # First: Find this user's proxy group.
        google_proxy_group_from_fence_db = (
            current_session.query(GoogleProxyGroup)
            .filter(GoogleProxyGroup.id == user.google_proxy_group_id)
            .first()
            # one_or_none() would be better, but is only in sqlalchemy 1.0.9
        )

        if google_proxy_group_from_fence_db:
            gpg_email = google_proxy_group_from_fence_db.email
            logger.debug("Found Google proxy group in Fence db: {}".format(gpg_email))
        else:
            # Construct the proxy group name that would have been used
            # and check if it exists in cirrus, in case Fence db just
            # didn't know about it.
            logger.debug(
                "Could not find Google proxy group for this user in Fence db. Checking cirrus..."
            )
            pgname = get_proxy_group_name_for_user(
                user.id, user.username, prefix=config["GOOGLE_GROUP_PREFIX"]
            )
            google_proxy_group_from_google = gcm.get_group(pgname)
            gpg_email = (
                google_proxy_group_from_google.get("email")
                if google_proxy_group_from_google
                else None
            )

        if not gpg_email:
            logger.info(
                "Could not find Google proxy group for user in Fence db or in cirrus. "
                "Assuming Google not in use as IdP. Proceeding with Fence deletes."
            )
        else:
            logger.debug(
                "Found Google proxy group email of user to delete: {}."
                "Proceeding with Google deletions.".format(gpg_email)
            )
            # Note: Fence db deletes here are interleaved with Google deletes.
            # This is so that if (for example) Google succeeds in deleting one SA
            # and then fails on the next, and the deletion process aborts, there
            # will not remain a record in Fence of the first, now-nonexistent SA.

            delete_google_service_accounts_and_keys(current_session, gcm, gpg_email)
            delete_google_proxy_group(
                current_session, gcm, gpg_email, google_proxy_group_from_fence_db, user
            )

    logger.debug("Deleting all user data from Fence database...")
    current_session.delete(user)
    current_session.commit()
    logger.info("Deleted all user data from Fence database. Returning.")

    return {"result": "success"}


def add_user_to_groups(current_session, username, groups=None):
    if not groups:
        groups = []
    usr = us.get_user(current_session, username)
    responses = []
    for groupname in groups:
        try:
            response = connect_user_to_group(current_session, usr, groupname)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    return {"result": responses}


def connect_user_to_group(current_session, usr, groupname=None):
    grp = gp.get_group(current_session, groupname)
    if not grp:
        raise UserError(("Group {0} doesn't exist".format(groupname)))
    else:
        responses = []
        responses.append(gp.connect_user_to_group(current_session, usr, grp))
        projects = gp.get_group_projects(current_session, groupname)
        projects_data = [
            pj.get_project(current_session, project).auth_id for project in projects
        ]
        projects_list = [
            {"auth_id": auth_id, "privilege": ["read"]} for auth_id in projects_data
        ]
        for project in projects_list:
            connect_user_to_project(current_session, usr, project)
        return responses


def remove_user_from_groups(current_session, username, groups=None):
    if not groups:
        groups = []
    usr = us.get_user(current_session, username)
    user_groups = us.get_user_groups(current_session, username)["groups"]
    groups_to_keep = [x for x in user_groups if x not in groups]

    projects_to_keep = {
        item
        for sublist in [
            gp.get_group_projects(current_session, x) for x in groups_to_keep
        ]
        for item in sublist
    }

    projects_to_remove = {
        item
        for sublist in [gp.get_group_projects(current_session, x) for x in groups]
        for item in sublist
        if item not in projects_to_keep
    }

    responses = []
    for groupname in groups:
        try:
            response = disconnect_user_from_group(current_session, usr, groupname)
            responses.append(response)
        except Exception as e:
            current_session.rollback()
            raise e
    for project in projects_to_remove:
        remove_user_from_project(current_session, usr, project)
    return {"result": responses}


def disconnect_user_from_group(current_session, usr, groupname):
    grp = gp.get_group(current_session, groupname)
    if not grp:
        return {"warning": ("Group {0} doesn't exist".format(groupname))}

    response = gp.remove_user_from_group(current_session, usr, grp)
    projects = gp.get_group_projects(current_session, groupname)
    projects_data = [
        pj.get_project(current_session, project).auth_id for project in projects
    ]
    return response


def remove_user_from_project(current_session, usr, project_name):
    proj = pj.get_project(current_session, project_name)
    us.remove_user_from_project(current_session, usr, proj)
