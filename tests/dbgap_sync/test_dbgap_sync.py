from fence import models


def test_sync_from_files(syncer, db_session):
    syncer.sync()
    user = db_session.query(models.User).filter_by(username='USERF').one()
    assert (
        user.project_access
        == {'TCGA-PCAWG': ['read-storage'], 'phs000178': ['read-storage']}
    )


def test_sync(syncer, db_session):
    s = db_session
    phsids = {
        'userA': ['phs000178', 'phs000179'],
        'userB': ['phs000179']
    }
    userinfo = {
        'userA': {'email': 'a@b'},
        'userB': {'email': 'a@b'},
    }

    syncer._init_projects(s)
    syncer.sync_to_db_and_storage_backend(phsids, userinfo, s)

    u = s.query(models.User).filter_by(username='userB').one()
    assert (
        u.project_access
        == {'phs000179': ['read-storage']}
    )


def test_sync_revoke(syncer, db_session):
    phsids = {
        'userA': ['phs000178', 'phs000179'],
        'userB': ['phs000179']
    }
    userinfo = {
        'userA': {'email': 'a@b'},
        'userB': {'email': 'a@b'},
    }
    phsids2 = {
        'userA': ['phs000179']
    }
    syncer._init_projects(db_session)
    syncer.sync_to_db_and_storage_backend(phsids, userinfo, db_session)

    syncer.sync_to_db_and_storage_backend(phsids2, userinfo, db_session)

    user_B = db_session.query(models.User).filter_by(username='userB').first()
    n_access_privilege = (
        db_session
        .query(models.AccessPrivilege)
        .filter_by(user_id=user_B.id)
        .count()
    )
    assert n_access_privilege == 0
