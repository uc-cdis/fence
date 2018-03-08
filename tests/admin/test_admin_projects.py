import fence.resources.admin as adm

def test_get_project(db_session, awg_users):
    info = adm.get_project_info(db_session, "test_project_1")
    assert info['name'] == 'test_project_1'
