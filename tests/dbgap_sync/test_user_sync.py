from fence import models


def test_sync(syncer, db_session):

    syncer.sync()

    user = db_session.query(models.User).filter_by(username='USERF').one()
    assert (
        user.project_access
        == {'phs000178': ['read-storage'], 'TCGA-PCAWG': ['read-storage']}
    )

    user = db_session.query(models.User).filter_by(username='USERB').one()
    assert (
        user.project_access
        == {'phs000179': ['read-storage'], 'TCGA-PCAWG': ['read-storage'],
            'phs000178': ['read-storage']}
    )

    user = db_session.query(models.User).filter_by(
        username='test_user1@gmail.com').one()

    user_access = db_session.query(
        models.AccessPrivilege).filter_by(user=user).all()

    assert (
        user_access[0].privilege
        == ['create', 'read', 'update', 'delete', 'upload']
        and len(user_access) == 1
    )

    user = db_session.query(models.User).filter_by(
        username='deleted_user@gmail.com').one()

    user_access = db_session.query(
        models.AccessPrivilege).filter_by(user=user).all()

    assert len(user_access) == 0


def test_sync_from_files(syncer, db_session):
    sess = db_session
    phsids = {
        'userA': {
            'phs000178': {'read-storage'},
            'phs000179': {'read-storage', 'write-storage'},
        },
        'userB': {
            'phs000179': {'read-storage', 'write-storage'},
        }
    }
    userinfo = {
        'userA': {'email': 'a@b'},
        'userB': {'email': 'a@b'},
    }

    syncer.sync_to_db_and_storage_backend(phsids, userinfo, sess)

    u = sess.query(models.User).filter_by(username='userB').one()
    u.project_access['phs000179'].sort()
    assert (
        u.project_access
        == {'phs000179': ['read-storage', 'write-storage']}
    )


def test_sync_revoke(syncer, db_session):
    phsids = {
        'userA': {
            'phs000178': {'read-storage'},
            'phs000179': {'read-storage', 'write-storage'},
        },
        'userB': {
            'phs000179': {'read-storage', 'write-storage'},
        }
    }
    userinfo = {
        'userA': {'email': 'a@b'},
        'userB': {'email': 'a@b'},
    }

    phsids2 = {
        'userA': {
            'phs000179': {'read-storage', 'write-storage'},
        }
    }

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


def test_sync_two_phsids_dict(syncer, db_session):

    phsids1 = {
        'userA': {
            'phs000178': {'read-storage'},
            'phs000179': {'read-storage', 'write-storage'},
        },
        'userB': {
            'phs000179': {'read-storage', 'write-storage'},
        }
    }

    phsids2 = {
        'userA': {
            'phs000180': {'read-storage', 'write-storage'},
        }
    }

    syncer.sync_two_phsids_dict(phsids1, phsids2)

    assert (
        phsids2
        == {'userB': {'phs000179': set(['read-storage', 'write-storage'])},
            'userA': {
            'phs000178': set(['read-storage']),
            'phs000179': set(['read-storage', 'write-storage']),
            'phs000180': set(['write-storage', 'read-storage'])},
            }
    )


def test_sync_two_phsids_dict_override(syncer, db_session):
    phsids1 = {
        'userA': {
            'phs000178': {'read-storage'},
            'phs000179': {'write-storage'},
        },
        'userB': {
            'phs000179': {'read-storage', 'write-storage'},
        }
    }

    phsids2 = {
        'userA': {
            'phs000179': {'read-storage'},
        }
    }

    syncer.sync_two_phsids_dict(phsids1, phsids2)

    assert (
        phsids2
        == {'userB': {'phs000179': set(['read-storage', 'write-storage'])},
            'userA': {
            'phs000178': set(['read-storage']),
            'phs000179': set(['read-storage', 'write-storage']), }
            }
    )


def test_sync_two_user_info(syncer, db_session):
    userinfo1 = {
        'userA': {'email': 'a@b'},
        'userB': {'email': 'a@b'},
    }

    userinfo2 = {
        'userC': {'email': 'a@b'},
    }
    syncer.sync_two_user_info_dict(userinfo1, userinfo2)

    assert (
        userinfo2
        == {'userA': {'email': 'a@b'},
            'userB': {'email': 'a@b'},
            'userC': {'email': 'a@b'},
            }
    )

    userinfo2 = {
        'userA': {'email': 'c@b'},
    }

    syncer.sync_two_user_info_dict(userinfo1, userinfo2)

    assert (
        userinfo2

        == {'userA': {'email': 'a@b'},
            'userB': {'email': 'a@b'},
            }
    )
