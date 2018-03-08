import fence.resources.admin as adm
from fence.models import User

def test_get_user(db_session, awg_users):
    info = adm.get_user_info(db_session, "awg_user")
    assert info['username'] == 'awg_user'
    assert info['role'] == 'user'
    assert "test_group_1" in info['groups']
    assert "test_group_2" in info['groups']
    assert info['message'] == ''
    assert info['email'] == None
    assert info['certificates_uploaded'] == []
    assert info['resources_granted'] == []
    assert info['project_access']['phs_project_1'] == ['read']
    assert info['project_access']['phs_project_2'] == ['read']


def test_add_user(db_session):
    adm.create_user(db_session, "insert_user", "insert_user@fake.com", "admin")
    user = db_session.query(User).filter(User.username == "insert_user").first()
    assert user.username == "insert_user"
