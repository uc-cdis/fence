import os
import pytest
import yaml

from fence import models
from fence.sync.sync_users import _format_policy_id

from tests.dbgap_sync.conftest import LOCAL_YAML_DIR


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_missing_file(syncer, monkeypatch, db_session):
    """
    Test that if the YAML file doesn't exist then the syncer doesn't do
    anything with the arborist client
    """
    monkeypatch.setattr(syncer, "sync_from_local_yaml_file", "this-file-is-not-real")
    # should fail gracefully
    syncer.sync()
    assert syncer.arborist_client.create_resource.not_called()
    assert syncer.arborist_client.create_role.not_called()
    assert syncer.arborist_client.create_policy.not_called()


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_incorrect_user_yaml_file(syncer, monkeypatch, db_session):
    """
    Test that if the YAML file doesn't exist then the syncer doesn't do
    anything with the arborist client
    """
    path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data/yaml/incorrect_user.yaml"
    )
    monkeypatch.setattr(syncer, "sync_from_local_yaml_file", path)
    # should fail gracefully
    syncer.sync()
    assert syncer.arborist_client.create_resource.not_called()
    assert syncer.arborist_client.create_role.not_called()
    assert syncer.arborist_client.create_policy.not_called()


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync(syncer, db_session, storage_client):

    syncer.sync()

    users = db_session.query(models.User).all()
    assert len(users) == 11

    tags = db_session.query(models.Tag).all()
    assert len(tags) == 7

    proj = db_session.query(models.Project).all()
    assert len(proj) == 9

    user = models.query_for_user(session=db_session, username="USERC")
    assert user.project_access == {
        "phs000178": ["read-storage"],
        "TCGA-PCAWG": ["read-storage"],
        "phs000179.c1": ["read-storage"],
    }

    user = models.query_for_user(session=db_session, username="USERF")
    assert user.project_access == {
        "phs000178.c1": ["read-storage"],
        "phs000178.c2": ["read-storage"],
    }

    user = models.query_for_user(session=db_session, username="TESTUSERB")
    assert user.project_access == {
        "phs000179.c1": ["read-storage"],
        "phs000178.c1": ["read-storage"],
    }

    user = models.query_for_user(session=db_session, username="TESTUSERD")
    assert user.display_name == "USER D"
    assert user.phone_number == "123-456-789"

    user = models.query_for_user(session=db_session, username="test_user1@gmail.com")
    user_access = db_session.query(models.AccessPrivilege).filter_by(user=user).all()
    assert set(user_access[0].privilege) == {
        "create",
        "read",
        "update",
        "delete",
        "upload",
    }
    assert len(user_access) == 1

    # TODO: check user policy access (add in user sync changes)

    user = models.query_for_user(session=db_session, username="deleted_user@gmail.com")
    assert not user.is_admin
    user_access = db_session.query(models.AccessPrivilege).filter_by(user=user).all()
    assert not user_access


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_from_files(syncer, db_session, storage_client):
    sess = db_session
    phsids = {
        "userA": {
            "phs000178": {"read-storage"},
            "phs000179": {"read-storage", "write-storage"},
        },
        "userB": {"phs000179": {"read-storage", "write-storage"}},
    }
    userinfo = {
        "userA": {"email": "a@b", "tags": {}},
        "userB": {"email": "a@b", "tags": {}},
    }

    syncer.sync_to_db_and_storage_backend(phsids, userinfo, {}, sess)

    u = models.query_for_user(session=db_session, username="userB")
    u.project_access["phs000179"].sort()
    assert u.project_access == {"phs000179": ["read-storage", "write-storage"]}


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_revoke(syncer, db_session, storage_client):
    phsids = {
        "userA": {
            "phs000178": {"read-storage"},
            "phs000179": {"read-storage", "write-storage"},
        },
        "userB": {"phs000179": {"read-storage", "write-storage"}},
    }
    userinfo = {
        "userA": {"email": "a@b", "tags": {}},
        "userB": {"email": "a@b", "tags": {}},
    }

    phsids2 = {"userA": {"phs000179": {"read-storage", "write-storage"}}}

    syncer.sync_to_db_and_storage_backend(phsids, userinfo, {}, db_session)
    syncer.sync_to_db_and_storage_backend(phsids2, userinfo, {}, db_session)

    user_B = models.query_for_user(session=db_session, username="userB")

    n_access_privilege = (
        db_session.query(models.AccessPrivilege).filter_by(user_id=user_B.id).count()
    )
    if n_access_privilege:
        raise AssertionError()


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_two_phsids_dict(syncer, db_session, storage_client):

    phsids1 = {
        "userA": {
            "phs000178": {"read-storage"},
            "phs000179": {"read-storage", "write-storage"},
        },
        "userB": {"phs000179": {"read-storage", "write-storage"}},
    }

    phsids2 = {"userA": {"phs000180": {"read-storage", "write-storage"}}}

    syncer.sync_two_phsids_dict(phsids1, phsids2)

    assert phsids2 == {
        "userB": {"phs000179": set(["read-storage", "write-storage"])},
        "userA": {
            "phs000178": set(["read-storage"]),
            "phs000179": set(["read-storage", "write-storage"]),
            "phs000180": set(["write-storage", "read-storage"]),
        },
    }


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_two_phsids_dict_override(syncer, db_session, storage_client):
    phsids1 = {
        "userA": {"phs000178": {"read-storage"}, "phs000179": {"write-storage"}},
        "userB": {"phs000179": {"read-storage", "write-storage"}},
    }

    phsids2 = {"userA": {"phs000179": {"read-storage"}}}

    syncer.sync_two_phsids_dict(phsids1, phsids2)

    assert phsids2 == {
        "userB": {"phs000179": set(["read-storage", "write-storage"])},
        "userA": {
            "phs000178": set(["read-storage"]),
            "phs000179": set(["read-storage", "write-storage"]),
        },
    }


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_two_user_info(syncer, db_session, storage_client):
    userinfo1 = {
        "userA": {
            "email": "a@email",
            "display_name": "user A",
            "phone_numer": "123-456-789",
            "role": "user",
        },
        "userB": {
            "email": "b@email",
            "display_name": "user B",
            "phone_numer": "232-456-789",
            "role": "admin",
        },
    }

    userinfo2 = {
        "userC": {
            "email": "c@email",
            "display_name": "user C",
            "phone_numer": "232-456-123",
            "role": "admin",
        }
    }
    syncer.sync_two_user_info_dict(userinfo1, userinfo2)

    assert userinfo2 == {
        "userA": {
            "email": "a@email",
            "display_name": "user A",
            "phone_numer": "123-456-789",
            "role": "user",
        },
        "userB": {
            "email": "b@email",
            "display_name": "user B",
            "phone_numer": "232-456-789",
            "role": "admin",
        },
        "userC": {
            "email": "c@email",
            "display_name": "user C",
            "phone_numer": "232-456-123",
            "role": "admin",
        },
    }

    userinfo2 = {
        "userA": {
            "email": "c@email",
            "display_name": "user C",
            "phone_numer": "232-456-123",
        }
    }

    syncer.sync_two_user_info_dict(userinfo1, userinfo2)

    assert userinfo2 == {
        "userA": {
            "email": "a@email",
            "display_name": "user A",
            "phone_numer": "123-456-789",
            "role": "user",
        },
        "userB": {
            "email": "b@email",
            "display_name": "user B",
            "phone_numer": "232-456-789",
            "role": "admin",
        },
    }
    userinfo2 = {
        "userA": {
            "email": "c@email",
            "display_name": "user C",
            "phone_numer": "232-456-123",
        }
    }

    syncer.sync_two_user_info_dict(userinfo2, userinfo1)
    assert userinfo1 == {
        "userA": {
            "email": "c@email",
            "display_name": "user C",
            "phone_numer": "232-456-123",
        },
        "userB": {
            "email": "b@email",
            "display_name": "user B",
            "phone_numer": "232-456-789",
            "role": "admin",
        },
    }


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_update_arborist(syncer, db_session):
    """
    Check that the ``syncer.arborist_client`` (which is a ``MagicMock``) is
    called appropriately. Also test that the policies for users are created in
    the database correctly, and registered to the User models.
    """
    syncer.sync()

    # These projects and permissions are collected from the syncer fixture. In
    # future should refactor to make project mapping its own fixture and not
    # duplicate in the tests here.

    # Check
    expect_resources = [
        "phs000179.c1",
        "phs000178.c1",
        "test",
        "phs000178.c2",
        "TCGA-PCAWG",
        "phs000178",
    ]
    for resource in expect_resources:
        assert syncer.arborist_client.create_resource.called_with(
            "/project", {"name": resource}
        )

    # Same with roles
    permissions = ["delete", "update", "upload", "create", "read", "read-storage"]
    expect_roles = [
        {
            "id": permission,
            "permissions": [
                {"id": permission, "action": {"method": permission, "service": ""}}
            ],
        }
        for permission in permissions
    ]
    for role in expect_roles:
        assert syncer.arborist_client.create_role.called_with(role)

    with open(LOCAL_YAML_DIR, "r") as f:
        user_data = yaml.safe_load(f)

    # TODO: update since policies are moved over to arborist now
    # should be part of user sync changes probably
