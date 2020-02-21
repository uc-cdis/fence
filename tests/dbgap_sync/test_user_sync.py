import os
import pytest
import yaml

from unittest.mock import MagicMock

from fence import models
from fence.sync.sync_users import _format_policy_id
from fence.config import config
from tests.dbgap_sync.conftest import LOCAL_YAML_DIR


def equal_project_access(d1, d2):
    """
    Check whether d1 and d2 are equal regardless of the order of list values.

    Args:
        d1, d2 (dict): { project1: [permission1, permission2], project2:...}

    Returns:
        boolean: True if d1 and d2 contain the same set of permissions for
        each project, False otherwise
    """
    try:
        assert len(d1.keys()) == len(d2.keys())
        for project, permissions in d1.items():
            assert project in d2
            assert sorted(permissions) == sorted(d2[project])
    except AssertionError:
        return False
    return True


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
@pytest.mark.parametrize("parse_consent_code_config", [False, True])
def test_sync(
    syncer, db_session, storage_client, parse_consent_code_config, monkeypatch
):
    # patch the sync to use the parameterized config value
    monkeypatch.setitem(
        syncer.dbGaP[0], "parse_consent_code", parse_consent_code_config
    )
    monkeypatch.setattr(syncer, "parse_consent_code", parse_consent_code_config)

    syncer.sync()

    users = db_session.query(models.User).all()
    assert len(users) == 11

    if parse_consent_code_config:
        user = models.query_for_user(session=db_session, username="USERC")
        assert equal_project_access(
            user.project_access,
            {
                "phs000178.c1": ["read", "read-storage"],
                "phs000178.c2": ["read", "read-storage"],
                "phs000178.c999": ["read", "read-storage"],
                "phs000179.c1": ["read", "read-storage"],
            },
        )

        user = models.query_for_user(session=db_session, username="USERF")
        assert equal_project_access(
            user.project_access,
            {
                "phs000178.c1": ["read", "read-storage"],
                "phs000178.c2": ["read", "read-storage"],
            },
        )

        user = models.query_for_user(session=db_session, username="TESTUSERB")
        assert equal_project_access(
            user.project_access,
            {
                "phs000179.c1": ["read", "read-storage"],
                "phs000178.c1": ["read", "read-storage"],
            },
        )
    else:
        user = models.query_for_user(session=db_session, username="USERC")
        assert equal_project_access(
            user.project_access,
            {
                "phs000178": ["read", "read-storage"],
                "TCGA-PCAWG": ["read", "read-storage"],
                "phs000179": ["read", "read-storage"],
            },
        )

        user = models.query_for_user(session=db_session, username="USERF")
        assert equal_project_access(
            user.project_access,
            {
                "phs000178": ["read", "read-storage"],
                "TCGA-PCAWG": ["read", "read-storage"],
            },
        )

        user = models.query_for_user(session=db_session, username="TESTUSERB")
        assert equal_project_access(
            user.project_access,
            {
                "phs000178": ["read", "read-storage"],
                "TCGA-PCAWG": ["read", "read-storage"],
                "phs000179": ["read", "read-storage"],
            },
        )

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


@pytest.mark.parametrize("syncer", ["google"], indirect=True)
@pytest.mark.parametrize("enable_common_exchange_area", [False, True])
@pytest.mark.parametrize("parse_consent_code_config", [False, True])
def test_dbgap_consent_codes(
    syncer,
    db_session,
    storage_client,
    enable_common_exchange_area,
    parse_consent_code_config,
    monkeypatch,
):
    # patch the sync to use the parameterized value for whether or not to parse exchange
    # area data

    # we moved to support multiple dbgap sftp servers, the config file has a list of dbgap
    # for local file dir, we only use the parameters from first dbgap config
    # hence only those are mocked here
    monkeypatch.setitem(
        syncer.dbGaP[0],
        "enable_common_exchange_area_access",
        enable_common_exchange_area,
    )
    monkeypatch.setattr(syncer, "parse_consent_code", parse_consent_code_config)
    monkeypatch.setitem(
        syncer.dbGaP[0], "parse_consent_code", parse_consent_code_config
    )

    monkeypatch.setattr(syncer, "project_mapping", {})

    syncer.sync()

    user = models.query_for_user(session=db_session, username="USERC")
    if parse_consent_code_config:
        if enable_common_exchange_area:
            # b/c user has c999, ensure they have access to all consents, study-specific
            # exchange area (via .c999) and the common exchange area configured
            assert equal_project_access(
                user.project_access,
                {
                    "phs000179.c1": ["read", "read-storage"],
                    "phs000178.c1": ["read", "read-storage"],
                    "phs000178.c2": ["read", "read-storage"],
                    "phs000178.c999": ["read", "read-storage"],
                    # should additionally include the study-specific exchange area access and
                    # access to the common exchange area
                    "test_common_exchange_area": ["read", "read-storage"],
                },
            )
        else:
            # b/c user has c999 but common exchange area is disabled, ensure they have
            # access to all consents, study-specific exchange area (via .c999)
            assert equal_project_access(
                user.project_access,
                {
                    "phs000179.c1": ["read", "read-storage"],
                    # c999 gives access to all consents
                    "phs000178.c1": ["read", "read-storage"],
                    "phs000178.c2": ["read", "read-storage"],
                    "phs000178.c999": ["read", "read-storage"],
                },
            )
    else:
        # with consent code parsing off, ensure users have access to just phsids
        assert equal_project_access(
            user.project_access,
            {
                "phs000178": ["read", "read-storage"],
                "phs000179": ["read", "read-storage"],
            },
        )

    user = models.query_for_user(session=db_session, username="USERF")
    if parse_consent_code_config:
        assert equal_project_access(
            user.project_access,
            {
                "phs000178.c1": ["read", "read-storage"],
                "phs000178.c2": ["read", "read-storage"],
            },
        )
    else:
        assert equal_project_access(
            user.project_access, {"phs000178": ["read", "read-storage"]}
        )

    user = models.query_for_user(session=db_session, username="TESTUSERB")
    if parse_consent_code_config:
        assert equal_project_access(
            user.project_access,
            {
                "phs000178.c1": ["read", "read-storage"],
                "phs000179.c1": ["read", "read-storage"],
            },
        )
    else:
        assert equal_project_access(
            user.project_access,
            {
                "phs000178": ["read", "read-storage"],
                "phs000179": ["read", "read-storage"],
            },
        )

    user = models.query_for_user(session=db_session, username="TESTUSERD")
    if parse_consent_code_config:
        assert equal_project_access(
            user.project_access, {"phs000179.c1": ["read", "read-storage"]}
        )
    else:
        assert equal_project_access(
            user.project_access, {"phs000179": ["read", "read-storage"]}
        )

    resource_to_parent_paths = {}
    for call in syncer.arborist_client.update_resource.call_args_list:
        args, kwargs = call
        parent_path = args[0]
        resource = args[1].get("name")
        resource_to_parent_paths.setdefault(resource, []).append(parent_path)

    if parse_consent_code_config:
        if enable_common_exchange_area:
            # b/c user has c999, ensure they have access to all consents, study-specific
            # exchange area (via .c999) and the common exchange area configured
            assert "phs000178.c999" in resource_to_parent_paths
            assert resource_to_parent_paths["phs000178.c999"] == ["/orgA/programs/"]

            assert "test_common_exchange_area" in resource_to_parent_paths
            assert resource_to_parent_paths["test_common_exchange_area"] == [
                "/dbgap/programs/"
            ]

        assert "phs000178.c1" in resource_to_parent_paths
        assert resource_to_parent_paths["phs000178.c1"] == ["/orgA/programs/"]

        # NOTE: this study+consent is configured to have multiple names in the dbgap config
        assert "phs000178.c2" in resource_to_parent_paths
        assert resource_to_parent_paths["phs000178.c2"] == [
            "/orgA/programs/",
            "/orgB/programs/",
            "/programs/",
        ]

        assert "phs000178.c999" in resource_to_parent_paths
        assert resource_to_parent_paths["phs000178.c999"] == ["/orgA/programs/"]

        assert "phs000179.c1" in resource_to_parent_paths
        assert resource_to_parent_paths["phs000179.c1"] == ["/orgA/programs/"]
    else:
        assert "phs000178" in resource_to_parent_paths
        # NOTE: this study is configured to have multiple names in the dbgap config
        assert resource_to_parent_paths["phs000178"] == [
            "/orgA/programs/",
            "/orgB/programs/",
            "/programs/",
        ]

        assert "phs000179" in resource_to_parent_paths
        assert resource_to_parent_paths["phs000179"] == ["/orgA/programs/"]


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_from_files(syncer, db_session, storage_client):
    sess = db_session
    phsids = {
        "userA": {
            "phs000178": {"read", "read-storage"},
            "phs000179": {"read", "read-storage", "write-storage"},
        },
        "userB": {"phs000179": {"read", "read-storage", "write-storage"}},
    }
    userinfo = {
        "userA": {"email": "a@b", "tags": {}},
        "userB": {"email": "a@b", "tags": {}},
    }

    syncer.sync_to_db_and_storage_backend(phsids, userinfo, sess)

    u = models.query_for_user(session=db_session, username="userB")
    assert equal_project_access(
        u.project_access, {"phs000179": ["read", "read-storage", "write-storage"]}
    )


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_revoke(syncer, db_session, storage_client):
    phsids = {
        "userA": {
            "phs000178": {"read", "read-storage"},
            "phs000179": {"read", "read-storage", "write-storage"},
        },
        "userB": {"phs000179": {"read", "read-storage", "write-storage"}},
    }
    userinfo = {
        "userA": {"email": "a@b", "tags": {}},
        "userB": {"email": "a@b", "tags": {}},
    }

    phsids2 = {"userA": {"phs000179": {"read", "read-storage", "write-storage"}}}

    syncer.sync_to_db_and_storage_backend(phsids, userinfo, db_session)
    syncer.sync_to_db_and_storage_backend(phsids2, userinfo, db_session)

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
            "phs000178": {"read", "read-storage"},
            "phs000179": {"read", "read-storage", "write-storage"},
        },
        "userB": {"phs000179": {"read", "read-storage", "write-storage"}},
    }

    phsids2 = {"userA": {"phs000180": {"read", "read-storage", "write-storage"}}}

    syncer.sync_two_phsids_dict(phsids1, phsids2)

    assert phsids2 == {
        "userB": {"phs000179": set(["read", "read-storage", "write-storage"])},
        "userA": {
            "phs000178": set(["read", "read-storage"]),
            "phs000179": set(["read", "read-storage", "write-storage"]),
            "phs000180": set(["write-storage", "read", "read-storage"]),
        },
    }


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_two_phsids_dict_combine(syncer, db_session, storage_client):
    phsids1 = {
        "userA": {
            "phs000178": {"read", "read-storage"},
            "phs000179": {"write-storage"},
        },
        "userB": {"phs000179": {"read", "read-storage", "write-storage"}},
    }

    phsids2 = {"userA": {"phs000179": {"read", "read-storage"}}}

    syncer.sync_two_phsids_dict(phsids1, phsids2)

    assert phsids2 == {
        "userB": {"phs000179": set(["read", "read-storage", "write-storage"])},
        "userA": {
            "phs000178": set(["read", "read-storage"]),
            "phs000179": set(["read", "read-storage", "write-storage"]),
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

    # one project is configured to point to two different arborist resource
    # parent paths (/orgA/ and /orgB/ and /)
    projects_with_mult_namespaces = ["phs000178.c2"]
    expect_resources = [
        "phs000179.c1",
        "phs000178.c1",
        "phs000178.c2",
        "phs000178.c999",
        "data_file",  # comes from user.yaml file
    ]

    resource_to_parent_paths = {}
    for call in syncer.arborist_client.update_resource.call_args_list:
        args, kwargs = call
        parent_path = args[0]
        resource = args[1].get("name")
        resource_to_parent_paths.setdefault(resource, []).append(parent_path)

    for resource in expect_resources:
        assert resource in list(resource_to_parent_paths.keys())
        if resource == "data_file":
            assert resource_to_parent_paths[resource] == ["/"]
        elif resource in projects_with_mult_namespaces:
            assert resource_to_parent_paths[resource] == [
                "/orgA/programs/",
                "/orgB/programs/",
                "/programs/",
            ]
        else:
            # configured default org path is OrgA
            assert resource_to_parent_paths[resource] == ["/orgA/programs/"]

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


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_merge_dbgap_servers(syncer, monkeypatch, db_session):
    """
    Test _merge_multiple_dbgap_sftp() is called when sync from dbgap server is true
    """
    monkeypatch.setattr(syncer, "is_sync_from_dbgap_server", True)

    def mock_merge(dbgap_servers, sess):
        return {}, {}

    syncer._merge_multiple_dbgap_sftp = MagicMock(side_effect=mock_merge)
    syncer._process_dbgap_files = MagicMock(side_effect=mock_merge)

    syncer.sync()
    syncer._merge_multiple_dbgap_sftp.assert_called_once_with(syncer.dbGaP, db_session)


@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_process_additional_dbgap_servers(syncer, monkeypatch, db_session):
    """
    Test that if there are additional dbgap servers,
    then process_dbgap_files() is called x times where x is # of dbgap servers
    """
    monkeypatch.setattr(syncer, "is_sync_from_dbgap_server", True)

    def mock_merge(dbgap_servers, sess):
        return {}, {}

    syncer._process_dbgap_files = MagicMock(side_effect=mock_merge)

    syncer.sync()

    # this function will be called once for each sftp server
    # the test config file has 2 dbgap sftp servers
    assert syncer._process_dbgap_files.call_count == 2
