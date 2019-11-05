from addict import Dict
from flask import url_for
import json
import jwt
import pytest

from unittest.mock import Mock, patch

from fence.config import config
from fence.models import (
    Bucket,
    Client,
    GoogleBucketAccessGroup,
    GoogleProxyGroup,
    GoogleProxyGroupToGoogleBucketAccessGroup,
    GoogleServiceAccount,
    GoogleServiceAccountKey,
    Group,
    User,
    UserGoogleAccount,
    UserGoogleAccountToProxyGroup,
    UserToGroup,
)
import fence.resources.admin as adm
from tests import utils


@pytest.fixture(autouse=True)
def mock_arborist(mock_arborist_requests):
    mock_arborist_requests()


# TODO: Not yet tested: PUT,DELETE /users/<username>/projects

# Move these fixtures to tests/conftest.py if they become useful elsewhere


@pytest.fixture
def admin_user(db_session):
    test_user = db_session.query(User).filter_by(username="admin_user").first()
    if not test_user:
        test_user = User(username="admin_user", id="5678", is_admin=True)
        db_session.add(test_user)
        db_session.commit()


@pytest.fixture(scope="function")
def encoded_admin_jwt(kid, rsa_private_key):
    """
    To use this fixture you need to also include admin_user as a fixture
    in your test (admin_user must be in the db).
    """
    headers = {"kid": kid}
    claims = utils.default_claims()
    claims["context"]["user"]["name"] = "admin_user@fake.com"
    claims["aud"].append("admin")
    claims["sub"] = "5678"
    claims["iss"] = config["BASE_URL"]
    claims["exp"] += 600
    return jwt.encode(
        claims, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")


# Dictionary for all these random magic numbers that the delete user
# tests/fixtures are using
userd_dict = {
    "user_id": 4242,
    "user_username": "test_user_d",
    "user_email": "test_user_d_email",
    "client_id": "dclientid",
    "group_id": 4240,
    "gpg_id": "d_gpgid",
    "gpg_email": "d_gpg_email",
    "gsa_id": 4202,
    "gsa_email": "d_sa_email",
    "gsak_id": 4201,
    "gsak_key_id": "d_sa_key",
    "bucket_id": 4203,
    "gbag_id": 4204,
    "gbag_email": "d_gbag_email",
    "gpg_to_gbag_id": 4205,
    "uga_id": 4206,
    "uga_email": "d_uga_email",
}


@pytest.fixture(scope="function")
def test_user_d(db_session):
    """
    Test user for delete /user/<username>
    For delete-user tests you probably want to just use
    one of the load_*_user_data fixtures
    """
    user = (
        db_session.query(User).filter_by(username=userd_dict["user_username"]).first()
    )
    if not user:
        user = User(
            id=userd_dict["user_id"],
            username=userd_dict["user_username"],
            email=userd_dict["user_email"],
        )
        db_session.add(user)
        db_session.commit()


@pytest.fixture(scope="function")
def load_non_google_user_data(db_session, test_user_d):
    """ Add general, non-Google user data to Fence db. """

    client = Client(
        client_id=userd_dict["client_id"],
        user_id=userd_dict["user_id"],
        issued_at=420,
        expires_at=42020,
        redirect_uri="dclient.com",
        grant_type="dgrant",
        response_type="dresponse",
        scope="dscope",
        name="dclientname",
        _allowed_scopes="dallscopes",
    )
    grp = Group(id=userd_dict["group_id"])
    usr_grp = UserToGroup(
        user_id=userd_dict["user_id"], group_id=userd_dict["group_id"]
    )
    db_session.add_all([client, grp, usr_grp])
    db_session.commit()


@pytest.fixture(scope="function")
def load_google_specific_user_data(db_session, test_user_d):
    """ Add Google-specific user data to Fence db."""

    gpg = GoogleProxyGroup(id=userd_dict["gpg_id"], email=userd_dict["gpg_email"])

    gsak = GoogleServiceAccountKey(
        id=userd_dict["gsak_id"],
        key_id=userd_dict["gsak_key_id"],
        service_account_id=userd_dict["gsa_id"],
    )
    gsa = GoogleServiceAccount(
        id=userd_dict["gsa_id"],
        google_unique_id="d_gui",
        user_id=userd_dict["user_id"],
        google_project_id="d_gpid",
        email=userd_dict["gsa_email"],
    )
    bkt = Bucket(id=userd_dict["bucket_id"])
    gbag = GoogleBucketAccessGroup(
        id=userd_dict["gbag_id"],
        bucket_id=userd_dict["bucket_id"],
        email=userd_dict["gbag_email"],
    )
    gpg_gbag = GoogleProxyGroupToGoogleBucketAccessGroup(
        id=userd_dict["gpg_to_gbag_id"],
        proxy_group_id=userd_dict["gpg_id"],
        access_group_id=userd_dict["gbag_id"],
    )
    uga = UserGoogleAccount(
        id=userd_dict["uga_id"],
        email=userd_dict["uga_email"],
        user_id=userd_dict["user_id"],
    )
    uga_pg = UserGoogleAccountToProxyGroup(
        user_google_account_id=userd_dict["uga_id"], proxy_group_id=userd_dict["gpg_id"]
    )
    db_session.add_all([gpg, gsak, gsa, bkt, gbag, gpg_gbag, uga, uga_pg])

    user = (
        db_session.query(User).filter_by(username=userd_dict["user_username"]).first()
    )
    user.google_proxy_group_id = userd_dict["gpg_id"]

    db_session.commit()


# GET /users/<username> tests


def test_get_user_username(
    client, admin_user, encoded_admin_jwt, db_session, test_user_a
):
    """ GET /users/<username>: [get_user]: happy path """
    r = client.get(
        "/admin/users/test_a", headers={"Authorization": "Bearer " + encoded_admin_jwt}
    )
    assert r.status_code == 200
    assert r.json["username"] == "test_a"


def test_get_user_long_username(
    client, admin_user, encoded_admin_jwt, db_session, test_user_long
):
    """ GET /users/<username>: [get_user]: happy path """
    r = client.get(
        "/admin/users/test_amazing_user_with_an_fancy_but_extremely_long_name",
        headers={"Authorization": "Bearer " + encoded_admin_jwt},
    )
    assert r.status_code == 200
    assert (
        r.json["username"] == "test_amazing_user_with_an_fancy_but_extremely_long_name"
    )


def test_get_user_username_nonexistent(
    client, admin_user, encoded_admin_jwt, db_session
):
    """ GET /users/<username>: [get_user]: When username does not exist """
    r = client.get(
        "/admin/users/test_nonexistent",
        headers={"Authorization": "Bearer " + encoded_admin_jwt},
    )
    assert r.status_code == 404


def test_get_user_username_noauth(client, db_session):
    """ GET /users/<username>: [get_user] but without authorization """
    # This creates a "test" user, so don't remove db_session fixture
    r = client.get("/admin/users/test_a")
    assert r.status_code == 401


# GET /user tests


def test_get_user(
    client,
    admin_user,
    encoded_admin_jwt,
    db_session,
    test_user_a,
    test_user_b,
    test_user_long,
):
    """ GET /user: [get_all_users] """
    r = client.get(
        "/admin/user", headers={"Authorization": "Bearer " + encoded_admin_jwt}
    )
    assert r.status_code == 200
    assert len(r.json["users"]) == 4
    usernames = [user["name"] for user in r.json["users"]]
    assert "test_a" in usernames
    assert "test_b" in usernames
    assert "test_amazing_user_with_an_fancy_but_extremely_long_name" in usernames
    assert "admin_user" in usernames


def test_get_user_noauth(client, db_session):
    """ GET /user: [get_all_users] but without authorization (access token) """
    r = client.get("/admin/user")
    assert r.status_code == 401


# POST /user tests


def test_post_user(client, admin_user, encoded_admin_jwt, db_session):
    """ POST /user: [create_user] """
    r = client.post(
        "/admin/user",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps(
            {"name": "new_test_user", "role": "user", "email": "new_test_user@fake.com"}
        ),
    )
    assert r.status_code == 200
    assert r.json["username"] == "new_test_user"
    assert r.json["is_admin"] == False
    assert r.json["role"] == "user"
    assert r.json["email"] == "new_test_user@fake.com"
    assert r.json["project_access"] == {}
    assert r.json["groups"] == []
    new_test_user = db_session.query(User).filter_by(username="new_test_user").one()
    assert new_test_user.username == "new_test_user"
    assert new_test_user.is_admin == False
    assert new_test_user.email == "new_test_user@fake.com"


def test_post_user_no_fields_defined(client, admin_user, encoded_admin_jwt, db_session):
    """ POST /user: [create_user] but no fields defined """
    r = client.post(
        "/admin/user",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({}),
    )
    assert r.status_code == 400


def test_post_user_only_email_defined(
    client, admin_user, encoded_admin_jwt, db_session
):
    """ POST /user: [create_user] only email defined (in particular, no username) """
    r = client.post(
        "/admin/user",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"email": "new_test_user@fake.com"}),
    )
    assert r.status_code == 400


def test_post_user_only_role_defined(client, admin_user, encoded_admin_jwt, db_session):
    """ POST /user: [create_user] only role defined (in particular, no username) """
    r = client.post(
        "/admin/user",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"role": "admin"}),
    )
    assert r.status_code == 400


def test_post_user_only_username_defined(
    client, admin_user, encoded_admin_jwt, db_session
):
    """ POST /user: [create_user] only username defined """
    r = client.post(
        "/admin/user",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"name": "new_test_user"}),
    )
    assert r.status_code == 200
    assert r.json["username"] == "new_test_user"
    assert r.json["is_admin"] == False
    assert r.json["role"] == "user"
    assert r.json["email"] == None
    assert r.json["project_access"] == {}
    assert r.json["groups"] == []
    new_test_user = db_session.query(User).filter_by(username="new_test_user").one()
    assert new_test_user.username == "new_test_user"
    assert new_test_user.is_admin == False
    assert new_test_user.email == None


def test_post_user_already_exists(
    client, admin_user, encoded_admin_jwt, test_user_a, db_session
):
    """ POST /user: [create_user] when user already exists """
    r = client.post(
        "/admin/user",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"name": "test_a"}),
    )
    assert r.status_code == 400


def test_post_user_noauth(client, db_session):
    """ POST /user: [create_user] but without authorization """
    r = client.post("/admin/user")
    assert r.status_code == 401


# PUT /users/<username> tests


def test_put_user_username(
    client, admin_user, encoded_admin_jwt, db_session, test_user_a
):
    """ PUT /users/<username>: [update_user] """
    r = client.put(
        "/admin/users/test_a",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps(
            {
                "name": "test_a_updated",
                "role": "admin",
                "email": "test_a_updated@fake.com",
            }
        ),
    )
    assert r.status_code == 200
    assert r.json["username"] == "test_a_updated"
    assert r.json["is_admin"] == True
    assert r.json["role"] == "admin"
    assert r.json["email"] == "test_a_updated@fake.com"
    assert r.json["project_access"] == {}
    assert r.json["groups"] == []
    updated_user = db_session.query(User).filter_by(username="test_a_updated").one()
    assert updated_user.username == "test_a_updated"
    assert updated_user.is_admin == True
    assert updated_user.email == "test_a_updated@fake.com"
    assert not db_session.query(User).filter_by(username="test_a").first()


def test_put_user_username_nonexistent(
    client, admin_user, encoded_admin_jwt, db_session
):
    """ PUT /users/<username>: [update_user] username to be updated doesn't exist"""
    r = client.put(
        "/admin/users/test_nonexistent",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"name": "test_nonexistent_updated"}),
    )
    assert r.status_code == 404
    assert (
        not db_session.query(User)
        .filter_by(username="test_nonexistent_updated")
        .first()
    )


def test_put_user_username_already_exists(
    client, admin_user, encoded_admin_jwt, db_session, test_user_a, test_user_b
):
    """ PUT /users/<username>: [update_user] desired new username already exists """
    r = client.put(
        "/admin/users/test_a",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"name": "test_b"}),
    )
    assert r.status_code == 400
    assert db_session.query(User).filter_by(username="test_a").one()
    assert db_session.query(User).filter_by(username="test_b").one()


def test_put_user_username_try_delete_username(
    client, admin_user, encoded_admin_jwt, db_session, test_user_a
):
    """ PUT /users/<username>: [update_user] try to delete username"""
    """
    This probably shouldn't be allowed. Conveniently, the code flow ends up
    the same as though the user had not tried to update 'name' at all,
    since they pass in None. Right now, this just returns a 200 without
    updating anything or sending any message to the user. So the test has
    been written to ensure this behavior, but maybe it should be noted that
    the tail wagged the dog somewhat in this case...
    """
    r = client.put(
        "/admin/users/test_a",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"name": None}),
    )
    assert r.status_code == 200
    user = db_session.query(User).filter_by(username="test_a").one()
    assert user.username == "test_a"


def test_put_user_username_try_delete_role(
    client, admin_user, encoded_admin_jwt, db_session, test_user_a
):
    """ PUT /users/<username>: [update_user] try to set role to None"""
    """
    This probably shouldn't be allowed. Conveniently, the code flow ends up
    the same as though the user had not tried to update 'role' at all,
    since they pass in None. Right now, this just returns a 200 without
    updating anything or sending any message to the user. So the test has
    been written to ensure this behavior, but maybe it should be noted that
    the tail wagged the dog somewhat in this case...
    """
    user = db_session.query(User).filter_by(username="test_a").one()
    original_isadmin = user.is_admin == True
    r = client.put(
        "/admin/users/test_a",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"role": None}),
    )
    assert r.status_code == 200
    assert user.is_admin == original_isadmin


def test_put_user_username_without_updating_username(
    client, admin_user, encoded_admin_jwt, db_session, test_user_a
):
    """ PUT /users/<username>: [update_user] update other fields but not username"""
    r = client.put(
        "/admin/users/test_a",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"email": "new_day_new_email@yay.com"}),
    )
    assert r.status_code == 200
    user = db_session.query(User).filter_by(username="test_a").one()
    assert user.email == "new_day_new_email@yay.com"


def test_put_user_username_try_delete_email(
    client, admin_user, encoded_admin_jwt, db_session, test_user_a
):
    """ PUT /users/<username>: [update_user] try to delete email"""
    r = client.put(
        "/admin/users/test_a",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"email": None}),
    )
    assert r.status_code == 200
    user = db_session.query(User).filter_by(username="test_a").one()
    assert user.email == None


def test_put_user_username_remove_admin_self(
    client, admin_user, encoded_admin_jwt, db_session
):
    """ PUT /users/<username>: [update_user] what if admin un-admins self?"""
    """ It seems this is fine. """
    r = client.put(
        "/admin/users/admin_user",
        headers={
            "Authorization": "Bearer " + encoded_admin_jwt,
            "Content-Type": "application/json",
        },
        data=json.dumps({"role": "user"}),
    )
    assert r.status_code == 200
    user = db_session.query(User).filter_by(username="admin_user").one()
    assert user.is_admin == False


def test_put_user_username_noauth(client, db_session):
    """ PUT /users/<username>: [update_user] but without authorization """
    r = client.put("/admin/users/test_a")
    assert r.status_code == 401


# DELETE /users/<username> tests


def assert_non_google_data_remained(db_session):
    """ Assert that test_user_d's non-Google data (client, group...) remain in Fence db. """
    client = db_session.query(Client).filter_by(client_id=userd_dict["client_id"]).all()
    assert len(client) == 1
    group = db_session.query(Group).filter_by(id=userd_dict["group_id"]).all()
    assert len(group) == 1
    usr_grp = (
        db_session.query(UserToGroup)
        .filter_by(user_id=userd_dict["user_id"], group_id=userd_dict["group_id"])
        .all()
    )
    assert len(usr_grp) == 1


def assert_non_google_data_deleted(db_session):
    """ Assert that test_user_d's non-Google data (client, group...) were removed from Fence db. """
    client = db_session.query(Client).filter_by(client_id=userd_dict["client_id"]).all()
    assert len(client) == 0
    group = db_session.query(Group).filter_by(id=userd_dict["group_id"]).all()
    assert len(group) == 1  # shouldn't get deleted
    usr_grp = (
        db_session.query(UserToGroup)
        .filter_by(user_id=userd_dict["user_id"], group_id=userd_dict["group_id"])
        .all()
    )
    assert len(usr_grp) == 0


def assert_google_service_account_data_remained(db_session):
    """ Assert that test_user_d's Google SA and its key remain in Fence db."""
    gsa = (
        db_session.query(GoogleServiceAccount).filter_by(id=userd_dict["gsa_id"]).all()
    )
    assert len(gsa) == 1
    gsak = (
        db_session.query(GoogleServiceAccountKey)
        .filter_by(id=userd_dict["gsak_id"])
        .all()
    )
    assert len(gsak) == 1


def assert_google_service_account_data_deleted(db_session):
    """ Assert that test_user_d's Google SA and its key are no longer in Fence db."""
    gsa = (
        db_session.query(GoogleServiceAccount).filter_by(id=userd_dict["gsa_id"]).all()
    )
    assert len(gsa) == 0
    gsak = (
        db_session.query(GoogleServiceAccountKey)
        .filter_by(id=userd_dict["gsak_id"])
        .all()
    )
    assert len(gsak) == 0


def assert_google_proxy_group_data_remained(db_session):
    """
    Assert that test_user_d's Google PG and all associated rows remain in Fence db.
    Also assert that the test bucket and GBAG remain.
    """
    gpg = db_session.query(GoogleProxyGroup).filter_by(id=userd_dict["gpg_id"]).all()
    assert len(gpg) == 1
    gpg_to_gbag = (
        db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup)
        .filter_by(id=userd_dict["gpg_to_gbag_id"])
        .all()
    )
    assert len(gpg_to_gbag) == 1
    uga_pg = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter_by(
            user_google_account_id=userd_dict["uga_id"],
            proxy_group_id=userd_dict["gpg_id"],
        )
        .all()
    )
    assert len(uga_pg) == 1
    uga = db_session.query(UserGoogleAccount).filter_by(id=userd_dict["uga_id"]).all()
    assert len(uga) == 1
    bkt = db_session.query(Bucket).filter_by(id=userd_dict["bucket_id"]).all()
    assert len(bkt) == 1
    gbag = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(id=userd_dict["gbag_id"])
        .all()
    )
    assert len(gbag) == 1


def assert_google_proxy_group_data_deleted(db_session):
    """
    Assert that test_user_d's Google PG and all associated rows removed from Fence db.
    But assert that the test bucket and GBAG remain.
    """
    gpg = db_session.query(GoogleProxyGroup).filter_by(id=userd_dict["gpg_id"]).all()
    assert len(gpg) == 0
    gpg_to_gbag = (
        db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup)
        .filter_by(id=userd_dict["gpg_to_gbag_id"])
        .all()
    )
    assert len(gpg_to_gbag) == 0
    uga_pg = (
        db_session.query(UserGoogleAccountToProxyGroup)
        .filter_by(
            user_google_account_id=userd_dict["uga_id"],
            proxy_group_id=userd_dict["gpg_id"],
        )
        .all()
    )
    assert len(uga_pg) == 0
    uga = db_session.query(UserGoogleAccount).filter_by(id=userd_dict["uga_id"]).all()
    assert len(uga) == 0
    bkt = db_session.query(Bucket).filter_by(id=userd_dict["bucket_id"]).all()
    assert len(bkt) == 1
    gbag = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(id=userd_dict["gbag_id"])
        .all()
    )
    assert len(gbag) == 1


def test_delete_user_username(
    client,
    admin_user,
    encoded_admin_jwt,
    db_session,
    load_non_google_user_data,
    load_google_specific_user_data,
    cloud_manager,
):
    """
    Case where Google is IDP and all as expected: Google data is in Fence and on Google,
    and all of the Google API calls via cirrus worked.
    Assert that all user data (Google and non-Google) cleared from Fence.
    """
    cloud_manager.return_value.__enter__.return_value.get_service_accounts_from_group.return_value = [
        "d_sa_email"
    ]
    cloud_manager.return_value.__enter__.return_value.delete_service_account.return_value = (
        {}
    )
    cloud_manager.return_value.__enter__.return_value.delete_group.return_value = {}

    r = client.delete(
        "/admin/users/test_user_d",
        headers={"Authorization": "Bearer " + encoded_admin_jwt},
    )

    assert r.status_code == 200
    assert_non_google_data_deleted(db_session)
    assert_google_service_account_data_deleted(db_session)
    assert_google_proxy_group_data_deleted(db_session)


def test_delete_user_username_no_google(
    client,
    admin_user,
    encoded_admin_jwt,
    db_session,
    load_non_google_user_data,
    cloud_manager,
):
    """
    Google is not being used as IDP, so GPG not found in Fence db;
    assert that non-Google Fence data is still deleted from Fence db.
    - No Google data in Fence db
    """
    # cirrus doesn't find GPG; no Google deletes attempted.
    cloud_manager.return_value.__enter__.return_value.get_group.return_value = None

    r = client.delete(
        "/admin/users/test_user_d",
        headers={"Authorization": "Bearer " + encoded_admin_jwt},
    )
    assert r.status_code == 200
    assert_non_google_data_deleted(db_session)


def test_delete_user_username_gpg_only_in_google(
    client,
    admin_user,
    encoded_admin_jwt,
    db_session,
    load_non_google_user_data,
    cloud_manager,
):
    """
    Google is IDP; GPG not found in Fence db for whatever reason,
    but found by cirrus in Google.
    Assert that non-Google Fence data is still deleted from Fence db.
    (And that Google data is deleted from Google,
    except that part isn't possible in a unit test.)
    - No Google data in Fence db
    """
    # cirrus finds GPG even though it wasn't in Fence. Actual GPG email doesn't matter
    # since we mock get_service_accounts_from_group anyway
    cloud_manager.return_value.__enter__.return_value.get_group.return_value = {
        "email": "d_gpg_email"
    }
    cloud_manager.return_value.__enter__.return_value.get_service_accounts_from_group.return_value = [
        "d_sa_email"
    ]
    cloud_manager.return_value.__enter__.return_value.delete_service_account.return_value = (
        {}
    )
    cloud_manager.return_value.__enter__.return_value.delete_group.return_value = {}

    r = client.delete(
        "/admin/users/test_user_d",
        headers={"Authorization": "Bearer " + encoded_admin_jwt},
    )
    assert r.status_code == 200
    assert_non_google_data_deleted(db_session)


def test_delete_user_username_with_sa_deletion_fail(
    client,
    admin_user,
    encoded_admin_jwt,
    db_session,
    load_non_google_user_data,
    load_google_specific_user_data,
    cloud_manager,
):
    """
    Case where service account deletion fails in Google.
    Assert that SA and SA key data, all other Google data,
    and all other non-Google data remained in Fence.
    """
    cloud_manager.return_value.__enter__.return_value.get_service_accounts_from_group.return_value = [
        "d_sa_email"
    ]
    cloud_manager.return_value.__enter__.return_value.delete_service_account.return_value = (
        "i am not an empty dict"
    )
    cloud_manager.return_value.__enter__.return_value.delete_group.return_value = {}

    r = client.delete(
        "/admin/users/test_user_d",
        headers={"Authorization": "Bearer " + encoded_admin_jwt},
    )

    assert r.status_code == 503
    assert_google_service_account_data_remained(db_session)
    assert_google_proxy_group_data_remained(db_session)
    assert_non_google_data_remained(db_session)


def test_delete_user_username_with_pg_deletion_fail(
    client,
    admin_user,
    encoded_admin_jwt,
    db_session,
    load_non_google_user_data,
    load_google_specific_user_data,
    cloud_manager,
):
    """
    Case where proxy group deletion fails in Google.
    Assert that SA and SA key data were deleted,
    but all other Google data present
    and all other non-Google data present too.
    """
    cloud_manager.return_value.__enter__.return_value.get_service_accounts_from_group.return_value = [
        "d_sa_email"
    ]
    cloud_manager.return_value.__enter__.return_value.delete_service_account.return_value = (
        {}
    )
    cloud_manager.return_value.__enter__.return_value.delete_group.return_value = (
        "i am not an empty dict"
    )

    r = client.delete(
        "/admin/users/test_user_d",
        headers={"Authorization": "Bearer " + encoded_admin_jwt},
    )

    assert r.status_code == 503
    assert_google_service_account_data_deleted(db_session)
    assert_google_proxy_group_data_remained(db_session)
    assert_non_google_data_remained(db_session)
