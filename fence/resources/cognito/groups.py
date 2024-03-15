from flask_sqlalchemy_session import current_session

import fence.scripting.fence_create


def sync_gen3_users_authz_from_adfs_groups(email, groups):
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
    # for each group, assign current user the following resources:
    # /cohort-middleware/{group}
    # with both role_ids: 'cohort_middleware_admin' and 'cohort_middleware_outputs_admin_reader'
    db_session = db_session or current_session
    _sync_adfs_groups(
        email,
        groups,
        db_session=db_session,
    )


def _sync_adfs_groups(gen3_user, groups, db_session=None):
    db_session = db_session or current_session

    default_args = fence.scripting.fence_create.get_default_init_syncer_inputs(
        authz_provider="Cognito"
    )
    syncer = fence.scripting.fence_create.init_syncer(**default_args)

    groups = syncer.sync_single_user_groups(
        gen3_user,
        groups,
    )
