from flask_sqlalchemy_session import current_session


def sync_gen3_users_authz_from_adfs_groups(email, groups, db_session=None):
    """
    Sync the authorization of users in the Gen3 database with the groups
    they are in on the ADFS server.

    Args:
        groups (list): list of groups to sync
        db_session (flask_sqlalchemy_session.SQLAlchemySession): db session to use

    Return:
        dict: dictionary of users that were synced and the groups they were
            synced with
    """
    db_session = db_session or current_session

    # for each group, assign current user the following resources:
    # /cohort-middleware/{group}
    # with both role_ids: 'cohort_middleware_admin' and 'cohort_middleware_outputs_admin_reader'
    for group in groups:
        pass
