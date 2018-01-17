from fence.data_model import models as udm


def test_sync_from_files(syncer):
    syncer.sync()
    with syncer.driver.session as s:
        u = s.query(udm.User).filter_by(username='USERF').one()
        assert (
            u.project_access
            == {'TCGA-PCAWG': ['read-storage'], 'phs000178': ['read-storage']}
        )


def test_sync(syncer):
    phsids = {
        'userA': ['phs000178', 'phs000179'],
        'userB': ['phs000179']
    }
    userinfo = {
        'userA': {'email': 'a@b'},
        'userB': {'email': 'a@b'},
    }

    with syncer.driver.session as s:
        syncer._init_projects(s)
        syncer.sync_to_db_and_storage_backend(phsids, userinfo, s)

    with syncer.driver.session as s:
        u = s.query(udm.User).filter_by(username='userB').one()
        assert (
            u.project_access
            == {'phs000179': ['read-storage']}
        )


def test_sync_revoke(syncer):
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
    with syncer.driver.session as s:
        syncer._init_projects(s)
        syncer.sync_to_db_and_storage_backend(phsids, userinfo, s)
    with syncer.driver.session as s:    
        syncer.sync_to_db_and_storage_backend(phsids2, userinfo, s)
    
    with syncer.driver.session as s:    
        u = s.query(udm.User).filter_by(username='userB').one()
        assert u.project_access == {}
