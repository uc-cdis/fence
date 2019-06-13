import fence.resources.admin as adm
from fence.models import Group, AccessPrivilege, Project, User
import pytest
from fence.errors import UserError, NotFound


def test_get_group(db_session, awg_users):
    info = adm.get_group_info(db_session, "test_group_2")
    assert info["name"] == "test_group_2"
    assert info["description"] == "the second test group"
    expected_projects = ["test_project_1", "test_project_2"]
    expected_projects.sort()
    info["projects"].sort()
    assert info["projects"] == expected_projects


def test_get_inexistent_group(db_session, awg_users):
    with pytest.raises(UserError):
        info = adm.get_group_info(db_session, "test_group_XXX")


def test_create_group(db_session):
    group = db_session.query(Group).filter_by(name="new_group_1").first()
    assert group == None
    adm.create_group(db_session, "new_group_1", "a new group")
    group = db_session.query(Group).filter_by(name="new_group_1").first()
    assert group.name == "new_group_1"
    assert group.description == "a new group"


def test_create_group_that_already_exists(db_session, awg_users):
    with pytest.raises(UserError):
        adm.create_group(db_session, "test_group_2", "a new group")


def test_delete_group(db_session, awg_groups):
    group = db_session.query(Group).filter_by(name="test_group_4").first()
    assert group.name == "test_group_4"
    adm.delete_group(db_session, "test_group_4")
    group = db_session.query(Group).filter_by(name="test_group_4").first()
    assert group == None


def test_update_group(db_session, awg_groups):
    group = db_session.query(Group).filter_by(name="test_group_4").first()
    assert group.name == "test_group_4"
    assert group.description == "the fourth test group"
    adm.update_group(db_session, "test_group_4", "the fifth test group", "test_group_5")
    group = db_session.query(Group).filter_by(name="test_group_4").first()
    assert group == None
    group = db_session.query(Group).filter_by(name="test_group_5").first()
    assert group.name == "test_group_5"
    assert group.description == "the fifth test group"


def test_add_project_to_group(db_session, awg_users, awg_groups):
    group = db_session.query(Group).filter_by(name="test_group_4").first()
    group_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(group_id=group.id).all()
    }
    expected_projects = {"test_project_6", "test_project_7"}
    assert expected_projects == group_projects
    adm.add_projects_to_group(db_session, "test_group_4", ["test_project_1"])
    group_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(group_id=group.id).all()
    }
    expected_projects = {"test_project_6", "test_project_7", "test_project_1"}
    assert expected_projects == group_projects


def test_add_project_to_group_updates_users(db_session, awg_users, awg_groups):
    user = db_session.query(User).filter_by(username="awg_user").first()
    user_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(user_id=user.id).all()
        if item.project_id != None
    }
    expected_projects = {"test_project_1", "test_project_2"}
    assert expected_projects == user_projects
    adm.add_projects_to_group(
        db_session, "test_group_1", ["test_project_6", "test_project_5"]
    )
    user_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(user_id=user.id).all()
        if item.project_id != None
    }
    expected_projects = {
        "test_project_1",
        "test_project_2",
        "test_project_5",
        "test_project_6",
    }
    assert expected_projects == user_projects


def test_delete_group_updates_user_projects(
    db_session, awg_users, awg_groups, oauth_client, mock_arborist_requests
):
    mock_arborist_requests()
    user = db_session.query(User).filter_by(username="awg_user").first()
    user_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(user_id=user.id).all()
        if item.project_id != None
    }
    expected_projects = {"test_project_1", "test_project_2"}
    assert expected_projects == user_projects

    adm.delete_group(db_session, "test_group_2")
    user_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(user_id=user.id).all()
        if item.project_id != None
    }
    expected_projects = {"test_project_1"}
    assert expected_projects == user_projects


def test_get_group_projects(db_session, awg_groups):
    group_projects = set(adm.get_group_projects(db_session, "test_group_4"))
    expected_projects = {"test_project_7", "test_project_6"}
    assert expected_projects == group_projects


def test_get_projects_from_inexistent_group(db_session, awg_groups):
    with pytest.raises(NotFound):
        group_projects = adm.get_group_projects(db_session, "test_group_XXX")


def test_remove_project_from_group(db_session, awg_groups):
    group = db_session.query(Group).filter_by(name="test_group_4").first()
    group_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(group_id=group.id).all()
    }
    expected_projects = {"test_project_6", "test_project_7"}
    assert expected_projects == group_projects
    adm.remove_projects_from_group(
        db_session, "test_group_4", ["test_project_6", "test_project_7"]
    )

    group_projects = {
        db_session.query(Project).filter_by(id == item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(group_id=group.id).all()
    }
    expected_projects = set()
    assert expected_projects == group_projects


def test_remove_project_from_group_updates_user(
    db_session, awg_users, awg_groups, oauth_client, mock_arborist_requests
):
    mock_arborist_requests()
    user = db_session.query(User).filter_by(username="awg_user").first()
    user_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(user_id=user.id).all()
    }
    expected_projects = {"test_project_1", "test_project_2"}
    assert expected_projects == user_projects
    adm.remove_projects_from_group(
        db_session, "test_group_2", ["test_project_1", "test_project_2"]
    )

    user_projects = {
        db_session.query(Project).filter_by(id=item.project_id).first().name
        for item in db_session.query(AccessPrivilege).filter_by(user_id=user.id).all()
    }
    expected_projects = {"test_project_1"}
    assert expected_projects == user_projects
