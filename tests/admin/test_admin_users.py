import pytest

import fence.resources.admin as adm
from fence.models import User, AccessPrivilege, Project, UserToGroup, Group
from fence.errors import NotFound, UserError


@pytest.fixture(autouse=True)
def mock_arborist(mock_arborist_requests):
    mock_arborist_requests()


def test_get_user(db_session, awg_users):
    info = adm.get_user_info(db_session, "awg_user")
    assert info["name"] == "awg_user"
    assert info["role"] == "user"
    assert "test_group_1" in info["groups"]
    assert "test_group_2" in info["groups"]
    assert info["message"] == ""
    assert info["email"] == None
    assert info["certificates_uploaded"] == []
    assert info["resources_granted"] == []
    assert info["project_access"]["phs_project_1"] == ["read"]
    assert info["project_access"]["phs_project_2"] == ["read"]


def test_create_user(db_session, oauth_client):
    adm.create_user(db_session, "insert_user", "admin", "insert_user@fake.com")
    user = db_session.query(User).filter(User.username == "insert_user").first()
    assert user.username == "insert_user"
    assert user.is_admin == True
    assert user.email == "insert_user@fake.com"


def test_delete_user(db_session, awg_users, cloud_manager):
    # cirrus doesn't find GPG; no Google deletes attempted.
    cloud_manager.return_value.__enter__.return_value.get_group.return_value = None

    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user != None
    user_id = user.id
    user_access = (
        db_session.query(AccessPrivilege)
        .filter(AccessPrivilege.user_id == user_id)
        .all()
    )
    assert user_access != []
    user_groups = (
        db_session.query(UserToGroup).filter(UserToGroup.user_id == user_id).all()
    )
    assert user_groups != []
    adm.delete_user(db_session, "awg_user")
    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user == None
    user_access = (
        db_session.query(AccessPrivilege)
        .filter(AccessPrivilege.user_id == user_id)
        .all()
    )
    assert user_access == []
    user_groups = (
        db_session.query(UserToGroup).filter(UserToGroup.user_id == user_id).all()
    )
    assert user_groups == []


def test_update_user_without_conflict(db_session, awg_users, oauth_client):
    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user != None
    adm.update_user(
        db_session, "awg_user", "admin", "new_email@fake.com", "new_awg_user"
    )
    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user == None
    user = db_session.query(User).filter(User.username == "new_awg_user").first()
    assert user.username == "new_awg_user"
    assert user.is_admin == True
    assert user.email == "new_email@fake.com"


def test_update_user_to_existing_name(db_session, awg_users):
    user = db_session.query(User).filter(User.username == "awg_user").first()
    assert user != None
    with pytest.raises(UserError):
        adm.update_user(
            db_session, "awg_user", "admin", "new_email@fake.com", "awg_user_2"
        )


def test_get_inexistent_user(db_session):
    with pytest.raises(NotFound):
        adm.get_user_info(db_session, "nonenone")


def test_create_already_existing_user(db_session, awg_users):
    with pytest.raises(UserError):
        adm.create_user(db_session, "awg_user", "admin", "insert_user@fake.com")


def test_get_all_users(db_session, awg_users):
    user_list = adm.get_all_users(db_session)
    user_name_list = [item["name"] for item in user_list["users"]]
    assert "awg_user" in user_name_list
    assert "awg_user_2" in user_name_list


def test_add_user_to_group(db_session, awg_users, awg_groups):
    accesses = (
        db_session.query(AccessPrivilege)
        .join(AccessPrivilege.user)
        .filter(User.username == "awg_user_2")
        .all()
    )
    assert accesses == []
    adm.add_user_to_groups(db_session, "awg_user_2", ["test_group_4"])
    accesses = (
        db_session.query(AccessPrivilege)
        .join(AccessPrivilege.user)
        .filter(User.username == "awg_user_2")
        .all()
    )
    projects = [
        db_session.query(Project).filter(Project.id == item.project_id).first().name
        for item in accesses
        if item.project_id != None
    ]
    assert "test_project_6" in projects
    assert "test_project_7" in projects
    group_access = (
        db_session.query(UserToGroup)
        .join(UserToGroup.user)
        .filter(User.username == "awg_user_2")
        .first()
    )
    assert (
        "test_group_4"
        == db_session.query(Group)
        .filter(Group.id == group_access.group_id)
        .first()
        .name
    )


def test_remove_user_from_group(db_session, awg_users, awg_groups):
    accesses = (
        db_session.query(AccessPrivilege)
        .join(AccessPrivilege.user)
        .filter(User.username == "awg_user")
        .all()
    )
    projects = [
        db_session.query(Project).filter(Project.id == item.project_id).first().name
        for item in accesses
        if item.project_id != None
    ]
    assert "test_project_1" in projects
    assert "test_project_2" in projects
    group_access = (
        db_session.query(UserToGroup)
        .join(UserToGroup.user)
        .filter(User.username == "awg_user")
        .all()
    )
    groups = [
        db_session.query(Group).filter(Group.id == group.group_id).first().name
        for group in group_access
    ]
    assert "test_group_1" in groups
    assert "test_group_2" in groups

    adm.remove_user_from_groups(
        db_session, "awg_user", ["test_group_1", "test_group_2"]
    )
    accesses = (
        db_session.query(AccessPrivilege)
        .join(AccessPrivilege.user)
        .filter(User.username == "awg_user")
        .all()
    )
    assert accesses == []
    group_access = (
        db_session.query(UserToGroup)
        .join(UserToGroup.user)
        .filter(User.username == "awg_user")
        .all()
    )
    assert group_access == []


def test_remove_user_from_wrong_group(db_session, awg_users, awg_groups):
    with pytest.raises(NotFound):
        adm.remove_user_from_groups(db_session, "awg_user", ["test_group_4"])


def test_get_user_groups(db_session, awg_users):
    groups = adm.get_user_groups(db_session, "awg_user")
    expected_groups = [
        {
            "name": "test_group_2",
            "description": "the second test group",
            "projects": ["test_project_1", "test_project_2"],
        },
        {
            "name": "test_group_1",
            "description": "the first test group",
            "projects": ["test_project_1"],
        },
    ]
    expected_groups.sort(key=lambda x: x["name"])
    groups["groups"].sort(key=lambda x: x["name"])
    assert groups["groups"] == expected_groups
