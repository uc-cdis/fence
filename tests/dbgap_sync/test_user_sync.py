import os
import pytest
import collections

import asyncio
from unittest.mock import MagicMock, patch
import mock
from userdatamodel.user import IdentityProvider

from fence import models
from fence.resources.google.access_utils import GoogleUpdateException
from fence.config import config
from fence.job.visa_update_cronjob import Visa_Token_Update
from fence.utils import DEFAULT_BACKOFF_SETTINGS

from tests.dbgap_sync.conftest import (
    get_test_encoded_decoded_visa_and_exp,
    fake_ras_login,
)
from tests.conftest import get_subjects_to_passports
from fence.models import User


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
    with pytest.raises(FileNotFoundError):
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
    with pytest.raises(AssertionError):
        syncer.sync()
    assert syncer.arborist_client.create_resource.not_called()
    assert syncer.arborist_client.create_role.not_called()
    assert syncer.arborist_client.create_policy.not_called()


@pytest.mark.parametrize("allow_non_dbgap_whitelist", [False, True])
@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
@pytest.mark.parametrize("parse_consent_code_config", [False, True])
@pytest.mark.parametrize("parent_to_child_studies_mapping", [False, True])
def test_sync(
    syncer,
    db_session,
    allow_non_dbgap_whitelist,
    storage_client,
    parse_consent_code_config,
    parent_to_child_studies_mapping,
    monkeypatch,
):
    # patch the sync to use the parameterized config value
    for dbgap_config in syncer.dbGaP:
        monkeypatch.setitem(
            dbgap_config, "parse_consent_code", parse_consent_code_config
        )
    monkeypatch.setitem(
        syncer.dbGaP[2], "allow_non_dbGaP_whitelist", allow_non_dbgap_whitelist
    )

    if parent_to_child_studies_mapping:
        mapping = {
            "phs001179": ["phs000179", "phs000178"],
        }
        monkeypatch.setitem(
            syncer.dbGaP[0],
            "parent_to_child_studies_mapping",
            mapping,
        )
        monkeypatch.setattr(syncer, "parent_to_child_studies_mapping", mapping)

    syncer.sync()

    users = db_session.query(models.User).all()

    # 5 from user.yaml, 6 from fake dbgap SFTP
    assert len(users) == 11

    if parse_consent_code_config:
        if allow_non_dbgap_whitelist:
            user = models.query_for_user(session=db_session, username="TESTUSERD")
            assert equal_project_access(
                user.project_access,
                {
                    "phs000179.c1": ["read", "read-storage"],
                    "PROJECT-12345": ["read", "read-storage"],
                },
            )

            user = models.query_for_user(session=db_session, username="TESTUSERB")
            assert equal_project_access(
                user.project_access,
                {
                    "phs000178.c1": ["read", "read-storage"],
                    "phs000179.c1": ["read", "read-storage"],
                    "PROJECT-12345": ["read", "read-storage"],
                },
            )

            user = models.query_for_user(session=db_session, username="USERC")
            assert equal_project_access(
                user.project_access,
                {
                    "phs000178.c1": ["read", "read-storage"],
                    "phs000178.c2": ["read", "read-storage"],
                    "phs000178.c999": ["read", "read-storage"],
                    "phs000179.c1": ["read", "read-storage"],
                    "PROJECT-12345": ["read", "read-storage"],
                    "test_common_exchange_area": ["read-storage", "read"],
                },
            )
        else:
            user = models.query_for_user(session=db_session, username="USERC")
            assert equal_project_access(
                user.project_access,
                {
                    "phs000178.c1": ["read", "read-storage"],
                    "phs000178.c2": ["read", "read-storage"],
                    "phs000178.c999": ["read", "read-storage"],
                    "phs000179.c1": ["read", "read-storage"],
                    "test_common_exchange_area": ["read", "read-storage"],
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
            if parent_to_child_studies_mapping:
                user = models.query_for_user(
                    session=db_session, username="TESTPARENTAUTHZ"
                )
                assert equal_project_access(
                    user.project_access,
                    {
                        "phs000178.c1": ["read", "read-storage"],
                        "phs000179.c1": ["read", "read-storage"],
                        "phs001179.c1": ["read", "read-storage"],
                    },
                )
                user = models.query_for_user(
                    session=db_session, username="TESTPARENTAUTHZ999"
                )
                assert equal_project_access(
                    user.project_access,
                    {
                        "phs000178.c1": ["read", "read-storage"],
                        "phs000178.c2": ["read", "read-storage"],
                        "phs000178.c999": ["read", "read-storage"],
                        "phs000179.c1": ["read", "read-storage"],
                        "phs000179.c999": ["read", "read-storage"],
                        "phs001179.c999": ["read", "read-storage"],
                        "phs001179.c1": ["read", "read-storage"],
                    },
                )
    else:
        if allow_non_dbgap_whitelist:
            user = models.query_for_user(session=db_session, username="TESTUSERD")
            assert equal_project_access(
                user.project_access,
                {
                    "phs000179": ["read", "read-storage"],
                    "PROJECT-12345": ["read", "read-storage"],
                },
            )

            user = models.query_for_user(session=db_session, username="TESTUSERB")
            assert equal_project_access(
                user.project_access,
                {
                    "phs000178": ["read", "read-storage"],
                    "phs000179": ["read", "read-storage"],
                    "PROJECT-12345": ["read", "read-storage"],
                    "TCGA-PCAWG": ["read", "read-storage"],
                },
            )

            user = models.query_for_user(session=db_session, username="USERC")
            assert equal_project_access(
                user.project_access,
                {
                    "phs000178": ["read", "read-storage"],
                    "phs000178": ["read", "read-storage"],
                    "phs000178": ["read", "read-storage"],
                    "phs000179": ["read", "read-storage"],
                    "TCGA-PCAWG": ["read", "read-storage"],
                    "PROJECT-12345": ["read", "read-storage"],
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
            if parent_to_child_studies_mapping:
                user = models.query_for_user(
                    session=db_session, username="TESTPARENTAUTHZ"
                )
                assert equal_project_access(
                    user.project_access,
                    {
                        "phs000178": ["read", "read-storage"],
                        "phs000179": ["read", "read-storage"],
                        "phs001179": ["read", "read-storage"],
                    },
                )
                user = models.query_for_user(
                    session=db_session, username="TESTPARENTAUTHZ999"
                )
                assert equal_project_access(
                    user.project_access,
                    {
                        "phs000178": ["read", "read-storage"],
                        "phs000179": ["read", "read-storage"],
                        "phs001179": ["read", "read-storage"],
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

    user = models.query_for_user(session=db_session, username="deleted_user@gmail.com")
    assert not user


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
    for dbgap_config in syncer.dbGaP:
        monkeypatch.setitem(
            dbgap_config, "parse_consent_code", parse_consent_code_config
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
            user.project_access,
            {
                "phs000178": ["read", "read-storage"],
            },
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
            user.project_access,
            {
                "phs000179.c1": ["read", "read-storage"],
            },
        )
    else:
        assert equal_project_access(
            user.project_access,
            {
                "phs000179": ["read", "read-storage"],
            },
        )

    resource_to_parent_paths = collections.defaultdict(list)
    for call in syncer._create_arborist_resources.call_args_list:
        args, kwargs = call
        full_paths = args[0]
        for full_path in full_paths:
            resource_begin = full_path.rfind("/") + 1
            parent_path = full_path[:resource_begin]
            resource = full_path[resource_begin:]
            resource_to_parent_paths[resource].append(parent_path)

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
def test_sync_with_google_errors(syncer, monkeypatch):
    """
    Verifies that errors from the bulk_update_google_groups method, specifically ones relating to Google APIs, do not
    prevent arborist updates from occuring.
    """
    monkeypatch.setitem(config, "GOOGLE_BULK_UPDATES", True)
    syncer._update_arborist = MagicMock()
    syncer._update_authz_in_arborist = MagicMock()

    with patch(
        "fence.sync.sync_users.update_google_groups_for_users"
    ) as mock_bulk_update:
        mock_bulk_update.side_effect = GoogleUpdateException("Something's Wrong!")
        with pytest.raises(GoogleUpdateException):
            syncer.sync()

    syncer._update_arborist.assert_called()
    syncer._update_authz_in_arborist.assert_called()


@patch("fence.sync.sync_users.paramiko.SSHClient")
@patch("os.makedirs")
@patch("os.path.exists", return_value=False)
@pytest.mark.parametrize("syncer", ["google", "cleversafe"], indirect=True)
def test_sync_with_sftp_connection_errors(
    mock_path, mock_makedir, mock_ssh_client, syncer, monkeypatch
):
    """
    Verifies that when there is an sftp connection error connection, that the connection is retried the max amount of
    tries as configured by DEFAULT_BACKOFF_SETTINGS
    """
    monkeypatch.setattr(syncer, "is_sync_from_dbgap_server", True)
    mock_ssh_client.return_value.__enter__.return_value.connect.side_effect = Exception(
        "Authentication timed out"
    )
    # usersync System Exits if any exception is raised during download.
    with pytest.raises(SystemExit):
        syncer.sync()
    assert (
        mock_ssh_client.return_value.__enter__.return_value.connect.call_count
        == DEFAULT_BACKOFF_SETTINGS["max_tries"]
    )


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

    resource_to_parent_paths = collections.defaultdict(list)
    for call in syncer.arborist_client.update_resource.call_args_list:
        args, kwargs = call
        parent_path = args[0]
        resource = args[1].get("name")
        resource_to_parent_paths.setdefault(resource, []).append(parent_path)
    # usersync updates dbgap projects at once using _create_arborist_resources
    # as opposed to individually with gen3authz's update_resource
    for call in syncer._create_arborist_resources.call_args_list:
        args, kwargs = call
        full_paths = args[0]
        for full_path in full_paths:
            resource_begin = full_path.rfind("/") + 1
            parent_path = full_path[:resource_begin]
            resource = full_path[resource_begin:]
            resource_to_parent_paths[resource].append(parent_path)

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
    # the test config file has 3 dbgap sftp servers
    assert syncer._process_dbgap_files.call_count == 3


def setup_ras_sync_testing(
    mock_discovery,
    mock_get_token,
    db_session,
    rsa_private_key,
    kid,
    mock_userinfo,
    mock_arborist_requests,
):
    """
    BEGIN Setup
    - make sure no app context
    - setup mock RAS responses for various users
        - setup fake access tokens
        - make userinfo respond with passport and visas (some valid, some expired, some invalid)
    """
    setup_info = {}

    mock_arborist_requests({"arborist/user/TESTUSERB": {"PATCH": (None, 204)}})
    mock_arborist_requests(
        {"arborist/user/test_user1@gmail.com": {"PATCH": (None, 204)}}
    )
    mock_arborist_requests({"arborist/user/TESTUSERD": {"PATCH": (None, 204)}})
    mock_arborist_requests({"arborist/user/USERF": {"PATCH": (None, 204)}})

    mock_discovery.return_value = "https://ras/token_endpoint"

    def get_token_response_for_user(*args, **kwargs):
        token_response = {
            "access_token": f"{args[0].username}",
            "id_token": f"{args[0].username}-id12345abcdef",
            "refresh_token": f"{args[0].username}-refresh12345abcdefg",
        }
        return token_response

    mock_get_token.side_effect = get_token_response_for_user

    usernames_to_ras_subjects = {
        "TESTUSERB": "sub-TESTUSERB-1234",
        "test_user1@gmail.com": "sub-test_user1@gmail.com-1234",
        "TESTUSERD": "sub-TESTUSERD-1234",
        "USERF": "sub-USERF-1234",
    }

    setup_info["usernames_to_ras_subjects"] = usernames_to_ras_subjects

    subjects_to_encoded_visas = {
        usernames_to_ras_subjects["TESTUSERB"]: [
            get_test_encoded_decoded_visa_and_exp(
                db_session,
                "TESTUSERB",
                rsa_private_key,
                kid,
                sub=usernames_to_ras_subjects["TESTUSERB"],
            )[0]
        ],
        usernames_to_ras_subjects["test_user1@gmail.com"]: [
            get_test_encoded_decoded_visa_and_exp(
                db_session,
                "test_user1@gmail.com",
                rsa_private_key,
                kid,
                expires=1,
                sub=usernames_to_ras_subjects["test_user1@gmail.com"],
            )[0]
        ],
        # note: get_test_encoded_decoded_visa_and_exp makes the visas for the next 2 users completely invalid
        usernames_to_ras_subjects["TESTUSERD"]: [
            get_test_encoded_decoded_visa_and_exp(
                db_session,
                "TESTUSERD",
                rsa_private_key,
                kid,
                sub=usernames_to_ras_subjects["TESTUSERD"],
                make_invalid=True,
            )[0]
        ],
        usernames_to_ras_subjects["USERF"]: [
            get_test_encoded_decoded_visa_and_exp(
                db_session,
                "USERF",
                rsa_private_key,
                kid,
                sub=usernames_to_ras_subjects["USERF"],
                make_invalid=True,
            )[0]
        ],
    }

    setup_info["subjects_to_encoded_visas"] = subjects_to_encoded_visas

    subjects_to_passports = get_subjects_to_passports(
        subjects_to_encoded_visas, kid=kid, rsa_private_key=rsa_private_key
    )

    setup_info["subjects_to_passports"] = subjects_to_passports

    def get_userinfo_for_user(*args, **kwargs):
        # username is the access token only b/c of the way the mocks are setup
        username = args[0]["access_token"]

        # sub is likely different than username
        sub = f"sub-{username}-1234"
        userinfo_response = {
            "sub": sub,
            "name": "",
            "preferred_username": "someuser@era.com",
            "UID": "",
            "UserID": username,
            "email": "",
        }
        subject_to_passports = subjects_to_passports.get(sub) or {}
        userinfo_response["passport_jwt_v11"] = subject_to_passports.get(
            "encoded_passport"
        )
        return userinfo_response

    mock_userinfo.side_effect = get_userinfo_for_user
    return setup_info


@pytest.mark.parametrize("syncer", ["cleversafe", "google"], indirect=True)
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_userinfo")
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_access_token")
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_user_sync_with_visa_sync_job(
    mock_discovery,
    mock_get_token,
    mock_userinfo,
    syncer,
    db_session,
    storage_client,
    monkeypatch,
    kid,
    rsa_public_key,
    rsa_private_key,
    mock_arborist_requests,
    no_app_context_no_public_keys,
):
    """
    Test that visas and authorization from them only get added to the database
    after visa sync job and not by usersync alone. Ensure usersync does not
    alter visa information.

    NOTE: syncer above creates users as if they already exist before this usersync
          and they have a specified IdP == RAS (e.g. they should get visas synced)
    """
    setup_info = setup_ras_sync_testing(
        mock_discovery,
        mock_get_token,
        db_session,
        rsa_private_key,
        kid,
        mock_userinfo,
        mock_arborist_requests,
    )

    # Usersync
    syncer.sync()

    users_after = db_session.query(models.User).all()

    # 5 from user.yaml, 6 from fake dbgap SFTP
    assert len(users_after) == 11

    for user in users_after:
        if user.username in setup_info["usernames_to_ras_subjects"]:
            # at this point, we will mock a login event by the user (at which point we'd get
            # a refresh token we can update visas with later)
            fake_ras_login(
                user.username,
                setup_info["usernames_to_ras_subjects"][user.username],
                db_session=db_session,
            )

        # make sure no one has visas yet
        assert not user.ga4gh_visas_v1

    # use refresh tokens from users to call access token polling "fence-create update-visa"
    # and sync authorization from visas
    job = Visa_Token_Update()
    job.pkey_cache = {
        "https://stsstg.nih.gov": {
            kid: rsa_public_key,
        }
    }
    loop = asyncio.get_event_loop()
    loop.run_until_complete(job.update_tokens(db_session))

    users_after_visas_sync = db_session.query(models.User).all()

    # now let's check that actual authorization / visas got added as expected
    valid_user = models.query_for_user(session=db_session, username="TESTUSERB")

    user_with_invalid_visa_also_in_telemetry_file = models.query_for_user(
        session=db_session, username="TESTUSERD"
    )

    user_with_invalid_visa_also_in_telemetry_file_2 = models.query_for_user(
        session=db_session, username="USERF"
    )

    user_with_expired_visa_also_in_telemetry_file = models.query_for_user(
        session=db_session,
        username="test_user1@gmail.com",
    )

    # make sure no access or visas for users not expected to have any
    assert (
        user_with_invalid_visa_also_in_telemetry_file
        and len(user_with_invalid_visa_also_in_telemetry_file.ga4gh_visas_v1) == 0
    )
    assert (
        user_with_invalid_visa_also_in_telemetry_file_2
        and len(user_with_invalid_visa_also_in_telemetry_file_2.ga4gh_visas_v1) == 0
    )
    assert (
        user_with_expired_visa_also_in_telemetry_file
        and len(user_with_expired_visa_also_in_telemetry_file.ga4gh_visas_v1) == 0
    )

    assert valid_user and valid_user.ga4gh_visas_v1
    assert len(valid_user.ga4gh_visas_v1) == 1
    assert (
        valid_user.ga4gh_visas_v1[0].ga4gh_visa
        in setup_info["subjects_to_encoded_visas"][
            setup_info["usernames_to_ras_subjects"][valid_user.username]
        ]
    )


@pytest.mark.parametrize("syncer", ["cleversafe", "google"], indirect=True)
def test_revoke_all_policies_no_user(db_session, syncer):
    """
    Test that function returns even when there's no user
    """
    # no arborist user with that username
    user_that_doesnt_exist = "foobar"
    syncer.arborist_client.get_user.return_value = None

    syncer._revoke_all_policies_preserve_mfa(user_that_doesnt_exist, "mock_idp")

    # we only care that this doesn't error
    assert True


@pytest.mark.parametrize("syncer", ["cleversafe", "google"], indirect=True)
def test_revoke_all_policies_preserve_mfa(monkeypatch, db_session, syncer):
    """
    Test that the mfa_policy is re-granted to the user after revoking all their policies.
    """
    monkeypatch.setitem(
        config,
        "OPENID_CONNECT",
        {
            "mock_idp": {
                "multifactor_auth_claim_info": {"claim": "acr", "values": ["mfa"]}
            }
        },
    )
    user = User(
        username="mockuser", identity_provider=IdentityProvider(name="mock_idp")
    )
    syncer.arborist_client.get_user.return_value = {"policies": ["mfa_policy"]}
    syncer._revoke_all_policies_preserve_mfa(user.username, user.identity_provider.name)
    syncer.arborist_client.revoke_all_policies_for_user.assert_called_with(
        user.username
    )
    syncer.arborist_client.grant_user_policy.assert_called_with(
        user.username, "mfa_policy"
    )


@pytest.mark.parametrize("syncer", ["cleversafe", "google"], indirect=True)
def test_revoke_all_policies_preserve_mfa_no_mfa(monkeypatch, db_session, syncer):
    """
    Test to ensure the mfa_policy preservation does not occur if the user does not have the mfa resource granted.
    """
    monkeypatch.setitem(
        config,
        "OPENID_CONNECT",
        {
            "mock_idp": {
                "multifactor_auth_claim_info": {"claim": "acr", "values": ["mfa"]}
            }
        },
    )
    user = User(
        username="mockuser", identity_provider=IdentityProvider(name="mock_idp")
    )
    syncer.arborist_client.list_resources_for_user.return_value = [
        "/programs/phs0001111"
    ]
    syncer._revoke_all_policies_preserve_mfa(user.username, user.identity_provider.name)
    syncer.arborist_client.revoke_all_policies_for_user.assert_called_with(
        user.username
    )
    syncer.arborist_client.grant_user_policy.assert_not_called()


@pytest.mark.parametrize("syncer", ["cleversafe", "google"], indirect=True)
def test_revoke_all_policies_preserve_mfa_no_idp(monkeypatch, db_session, syncer):
    """
    Tests for when no IDP is associated with the user
    """
    monkeypatch.setitem(
        config,
        "OPENID_CONNECT",
        {
            "mock_idp": {
                "multifactor_auth_claim_info": {"claim": "acr", "values": ["mfa"]}
            }
        },
    )
    user = User(username="mockuser")
    syncer._revoke_all_policies_preserve_mfa(user.username)
    syncer.arborist_client.revoke_all_policies_for_user.assert_called_with(
        user.username
    )
    syncer.arborist_client.grant_user_policy.assert_not_called()
    syncer.arborist_client.list_resources_for_user.assert_not_called()


@pytest.mark.parametrize("syncer", ["cleversafe", "google"], indirect=True)
def test_revoke_all_policies_preserve_mfa_ensure_revoke_on_error(
    monkeypatch, db_session, syncer
):
    """
    Tests that arborist_client.revoke_all_policies is still called when an error occurs
    """
    monkeypatch.setitem(
        config,
        "OPENID_CONNECT",
        {
            "mock_idp": {
                "multifactor_auth_claim_info": {"claim": "acr", "values": ["mfa"]}
            }
        },
    )
    user = User(
        username="mockuser", identity_provider=IdentityProvider(name="mock_idp")
    )
    syncer.arborist_client.list_resources_for_user.side_effect = Exception(
        "Unknown error"
    )
    syncer._revoke_all_policies_preserve_mfa(user.username, user.identity_provider.name)
    syncer.arborist_client.revoke_all_policies_for_user.assert_called_with(
        user.username
    )
