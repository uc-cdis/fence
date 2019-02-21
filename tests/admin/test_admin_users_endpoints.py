from addict import Dict
from flask import url_for
import json
import jwt
import pytest

from fence.config import config
from fence.models import User
import fence.resources.admin as adm
from tests import utils

# TODO: Not yet tested: PUT,DELETE /users/<username>/projects
# TODO: Not yet tested: DELETE /users/<username>/

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
    headers = {"kid": kid}
    claims = utils.default_claims()
    claims["context"]["user"]["name"] = "admin_user@fake.com"
    claims["aud"].append("admin")
    claims["sub"] = "5678"
    claims["iss"] = config["BASE_URL"]
    claims["exp"] += 600
    return jwt.encode(claims, key=rsa_private_key, headers=headers, algorithm="RS256")


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
    client, admin_user, encoded_admin_jwt, db_session, test_user_a, test_user_b
):
    """ GET /user: [get_all_users] """
    r = client.get(
        "/admin/user", headers={"Authorization": "Bearer " + encoded_admin_jwt}
    )
    assert r.status_code == 200
    assert len(r.json["users"]) == 3
    usernames = [user["name"] for user in r.json["users"]]
    assert "test_a" in usernames
    assert "test_b" in usernames
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
