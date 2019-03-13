from cirrus import GoogleCloudManager
from cirrus.google_cloud.manager import _get_proxy_group_name_for_user
from fence.config import config
from fence.errors import NotFound, UserError
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


def delete_user(current_session, username):
    """
    Remove a user from both the userdatamodel
    and the associated storage for that project/bucket.
    Returns a dictionary.
    """
    """
    Much of the strangeness in the following code stems from the
    fact that we are not confident the Fence db will always be in
    perfect sync with Google, and we err on the side of safety
    (we prioritise making sure user is really cleared out of Google
    to prevent unauthorized data access issues; we refer to
    cirrus/Google instead of the Fence db in cases where both
    would be possible).
    So, if the Fence-Google sync situation changes,
    do edit this code accordingly.
    """

    capp.logger.debug("Beginning delete user.")

    with GoogleCloudManager() as gcm:

        # Delete user's service accounts, SA keys, user proxy group from Google.
        # Noop if Google not in use.
        # Note: Fence db deletes are interleaved with Google deletes.
        # This is to avoid leaving records in Fence of deleted Google entities
        # in the case where a Google delete fails after others have succeeded
        # and the delete aborts.
        # The Google deletes here are not factored out into a different function
        # in order to not obfuscate the interwoven Fence db deletes.

        user = query_for_user(session=current_session, username=username)
        if not user:
            raise NotFound("".join(["user name ", username, " not found"]))

        capp.logger.debug("Found user in Fence db: {}".format(user))

        # First: Find this user's proxy group.
        google_proxy_group_f = (
            current_session.query(GoogleProxyGroup)
            .filter(GoogleProxyGroup.id == user.google_proxy_group_id)
            .first()
            # one_or_none() would be better, but is only in sqlalchemy 1.0.9
        )

        if google_proxy_group_f:
            gpg_email = google_proxy_group_f.email
            capp.logger.debug(
                "Found Google proxy group in Fence db: {}".format(gpg_email)
            )
        else:
            # Construct the proxy group name that would have been used
            # and check if it exists in cirrus, in case Fence db just
            # didn't know about it.
            capp.logger.debug(
                "Could not find Google proxy group for this user in Fence db. Checking cirrus..."
            )
            pgname = _get_proxy_group_name_for_user(
                user.id, user.username, prefix=config["GOOGLE_GROUP_PREFIX"]
            )
            google_proxy_group_g = gcm.get_group(pgname)
            gpg_email = google_proxy_group_g.get("email") if google_proxy_group_g else None

        if not gpg_email:
            capp.logger.info(
                "Could not find Google proxy group for user in Fence db or in cirrus. "
                "Assuming Google not in use as IdP. Proceeding with Fence deletes."
            )
        else:
            capp.logger.debug(
                "Found Google proxy group email of user to delete: {}."
                "Proceeding with Google deletions. Deleting all associated "
                "service accounts...".format(gpg_email)
            )
            # Choosing to refer to cirrus instead of fence db for the list of SAs.
            service_account_emails = gcm.get_service_accounts_from_group(gpg_email)

            for sae in service_account_emails:
                # Upon deletion of a service account, Google will
                # automatically delete all key IDs associated with that
                # service account. So we skip doing that here.
                capp.logger.debug(
                    "Attempting to delete Google service account with email {} "
                    "along with all associated service account keys...".format(
                        sae
                    )
                )
                r = gcm.delete_service_account(sae)

                if r == {}:
                    capp.logger.info(
                        "Google service account with email {} successfully removed "
                        "from Google, along with all associated service account keys.".format(
                            sae
                        )
                    )
                    capp.logger.debug(
                        "Attempting to clear records from Fence database..."
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
                        capp.logger.info(
                            "Records for service account {} successfully cleared from Fence database.".format(
                                sae
                            )
                        )
                    else:
                        capp.logger.info(
                            "Records for service account {} NOT FOUND in Fence database. "
                            "Continuing anyway.".format(
                                sae
                            )
                        )

                else:
                    raise UnavailableError(
                        "Error: Google unable to delete service account {}. Aborting".format(
                            sae
                        )
                    )

            # Next, delete the proxy group. Google will automatically remove
            # this proxy group from all GBAGs the proxy group is a member of.
            # So we skip doing that here.
            capp.logger.debug(
                "Attempting to delete Google proxy group with email {}...".format(
                    gpg_email
                )
            )
            r = gcm.delete_group(gpg_email)

            if r == {}:
                capp.logger.info(
                    "Google proxy group with email {} successfully removed from Google.".format(
                        gpg_email
                    )
                )
                if google_proxy_group_f:
                    # (else it was google_proxy_group_*g* and there is nothing to delete in Fence db.)
                    capp.logger.debug(
                        "Attempting to clear records from Fence database..."
                    )
                    capp.logger.debug(
                        "Deleting rows in google_proxy_group_to_google_bucket_access_group..."
                    )
                    gpg_to_gbag = (
                        current_session.query(GoogleProxyGroupToGoogleBucketAccessGroup)
                        .filter(
                            GoogleProxyGroupToGoogleBucketAccessGroup.proxy_group_id
                            == google_proxy_group_f.id
                        )
                        .all()
                    )
                    for row in gpg_to_gbag:
                        current_session.delete(row)
                    capp.logger.debug(
                        "Deleting rows in user_google_account_to_proxy_group..."
                    )
                    uga_to_pg = (
                        current_session.query(UserGoogleAccountToProxyGroup)
                        .filter(
                            UserGoogleAccountToProxyGroup.proxy_group_id
                            == google_proxy_group_f.id
                        )
                        .all()
                    )
                    for row in uga_to_pg:
                        current_session.delete(row)
                    capp.logger.debug("Deleting rows in user_google_account...")
                    uga = (
                        current_session.query(UserGoogleAccount)
                        .filter(UserGoogleAccount.user_id == user.id)
                        .all()
                    )
                    for row in uga:
                        current_session.delete(row)
                    capp.logger.debug("Deleting row in google_proxy_group...")
                    current_session.delete(google_proxy_group_f)
                    current_session.commit()
                    capp.logger.info(
                        "Records for Google proxy group {} successfully cleared from Fence "
                        "database, along with associated user Google accounts.".format(
                            gpg_email
                        )
                    )
                    capp.logger.info("Done with Google deletions.")
            else:
                raise UnavailableError(
                    "Error: Google unable to delete proxy group {}. Aborting".format(
                        gpg_email
                    )
                )

    # Note: ZLC 2019-03-04 Currently Fence db has users_to_policies table and policy table,
    # where policy table, for some reason, has a user_id field.
    # Moreover, that user_id field is _not_ a foreign key referencing User.id.
    # Presumably rows in the policy table should get deleted when the user they reference is deleted,
    # but we cannot rely on a delete cascade for this, since the policy table is
    # not a child of any other table.
    # So there should be custom logic here to delete rows in the policy table.
    # However, apparently we will soon remove this table from Fence anyway.
    # TODO: So when that happens, remove this comment block.
    # Meanwhile, note that this code does _not_ delete rows in the policy table.

    capp.logger.debug("Deleting all user data from Fence database...")
    current_session.delete(user)
    current_session.commit()
    capp.logger.info("Deleted all user data from Fence database. Returning.")

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
