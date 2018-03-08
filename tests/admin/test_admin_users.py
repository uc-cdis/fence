import fence.resources.admin as adm
from fence.models import User
import pytest
from fence.errors import NotFound


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


def test_create_user(db_session):
    adm.create_user(db_session, "insert_user", "admin", "insert_user@fake.com")
    user = db_session.query(User).filter(User.username == "insert_user").first()
    assert user.username == "insert_user"
    assert user.is_admin == True
    assert user.email == "insert_user@fake.com"


def test_delete_user(db_session, awg_users):
    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user != None
    adm.delete_user(db_session, "awg_user")
    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user == None


def test_update_user(db_session, awg_users):
    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user != None
    adm.update_user(db_session, "awg_user", "admin", "new_email@fake.com", "new_awg_user")
    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user == None
    user = db_session.query(User).filter(User.username == "new_awg_user").first()
    assert user.username == "new_awg_user"
    assert user.is_admin == True
    assert user.email == "new_email@fake.com"


def test_get_inexistent_user(db_session):
    with pytest.raises(NotFound):
        adm.get_user_info(db_session, "nonenone")
