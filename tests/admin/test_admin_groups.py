import fence.resources.admin as adm

def test_get_group(db_session, awg_users):
    info = adm.get_group_info(db_session, "test_group_1")
    assert info['name'] == 'test_group_1'
