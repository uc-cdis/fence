from addict import Dict
from flask import url_for
import json
import jwt
import pytest

from fence.config import config
from fence.models import User  #, AccessPrivilege, Project, UserToGroup, Group
import fence.resources.admin as adm
from tests import utils

import pdb # TODO REMOVE
from flask_sqlalchemy_session import current_session #TODO db hack; remove

# DATABASE:
# The extant db_session fixture yields one db_session, function-scoped,
# that is different from the current_session used by the admin code
# (= the current_session from flask_sqlalchemy_session).
# If I $psql fence_test_tmp and select * from "User";
# The tables only get populated if the fixtures commit to current_session.
# Which obv doesn't work for testing purposes.
# TODO: Figure this out then clean up fixtures

# TODO: Most of the 500s mentioned below stem from the same code; see PXP-2374

"""
QUESTIONS:
  - About the database situation.
  - Are tests on right track in terms of scope, assertion style, etc?
  - Story scope
"""

# Move these fixtures to tests/conftest.py if they become useful elsewhere

@pytest.fixture
def admin_user(db_session):
    #test_user = db_session.query(User).filter_by(username="admin_user").first()
    #if not test_user:
    #    test_user = User(username="admin_user", id="5678", is_admin=True)
    #    db_session.add(test_user)
    #    db_session.commit()
    # TODO Database hack. Remove when fixed
    test_user = current_session.query(User).filter_by(username="admin_user").first()
    if not test_user:
        test_user = User(username="admin_user", id="5678", is_admin=True)
        current_session.add(test_user)
        current_session.commit()


@pytest.fixture(scope="function")
def encoded_admin_jwt(kid, rsa_private_key):
    headers = {"kid": kid}
    claims = utils.default_claims()
    claims["context"]["user"]["name"] = "admin_user@fake.com"
    claims["aud"].append("admin")
    claims["sub"] = "5678"
    claims["iss"] = config["BASE_URL"]
    claims["exp"] += 6000 # TODO 600 but this dies while I pdb :P
    return jwt.encode(claims, key=rsa_private_key, headers=headers, algorithm="RS256")


# TODO: Remove this once db situation is fixed
# It currently "overwrites" the same thing in conftest but uses current_session
@pytest.fixture(scope="function")
def test_user_a(db_session):
    test_user = current_session.query(User).filter_by(username="test_a").first()
    if not test_user:
        test_user = User(username="test_a", is_admin=False)
        current_session.add(test_user)
        current_session.commit()
    return Dict(username="test_a", user_id=test_user.id)


# TODO: Remove this once db situation is fixed
@pytest.fixture(scope="function")
def test_user_b(db_session):
    test_user = current_session.query(User).filter_by(username="test_b").first()
    if not test_user:
        test_user = User(username="test_b", is_admin=False)
        current_session.add(test_user)
        current_session.commit()
    return Dict(username="test_b", user_id=test_user.id)


# GET /user/<username> tests

def test_get_user_username(client, admin_user, encoded_admin_jwt, test_user_a):
    """ GET /user/<username>: [get_user]: happy path """
    r = client.get(
            '/admin/user/test_a',
            headers={"Authorization": "Bearer " + encoded_admin_jwt}
        )
    assert r.status_code == 200
    assert r.json['username'] == 'test_a'


def test_get_user_username_nonexistent(client, admin_user, encoded_admin_jwt):
    """ GET /user/<username>: [get_user]: When username does not exist """
    r = client.get(
            '/admin/user/test_nonexistent',
            headers={"Authorization": "Bearer " + encoded_admin_jwt}
        )
    assert r.status_code == 404


def test_get_user_username_noauth(client):
    """ GET /user/<username>: [get_user] but without authorization """
    r = client.get('/admin/user/test_a')
    assert r.status_code == 401


# GET /user tests

def test_get_user(client, admin_user, encoded_admin_jwt, test_user_a, test_user_b):
    """ GET /user: [get_all_users] """
    r = client.get(
            '/admin/user',
            headers={"Authorization": "Bearer " + encoded_admin_jwt}
        )
    assert r.status_code == 200
    assert len(r.json['users']) == 3
    usernames = [user['name'] for user in r.json['users']]
    assert 'test_a' in usernames
    assert 'test_b' in usernames
    assert 'admin_user' in usernames


def test_get_user_noauth(client):
    """ GET /user: [get_all_users] but without authorization (access token) """
    r = client.get('/admin/user')
    assert r.status_code == 401


# POST /user tests

def test_post_user(client, admin_user, encoded_admin_jwt, db_session):
    """ POST /user: [create_user] """
    r = client.post(
            '/admin/user',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "name": "new_test_user",
                "role": "user",
                "email": "new_test_user@fake.com"
            })
        )
    assert r.status_code == 200
    assert r.json['username'] == 'new_test_user'
    assert r.json['is_admin'] == False
    assert r.json['role'] == 'user'
    assert r.json['email'] == 'new_test_user@fake.com'
    assert r.json['project_access'] == {}
    assert r.json['groups'] == []
    new_test_user = db_session.query(User).filter_by(username="new_test_user").one()
    assert new_test_user.username == 'new_test_user'
    assert new_test_user.is_admin == False
    assert new_test_user.email == 'new_test_user@fake.com'


def test_post_user_no_fields_defined(client, admin_user, encoded_admin_jwt, db_session):
    # TODO: 500 needs fixed and then test needs renamed/rewritten
    """ POST /user: [create_user] but no fields defined """
    r = client.post(
            '/admin/user',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({})
        )
    # TODO: Unsure what we want to do here.
    # TODO: Write asserts once find this ^ out.
    assert True


def test_post_user_one_field_defined(client, admin_user, encoded_admin_jwt, db_session):
    """ POST /user: [create_user] only username defined """
    # TODO: IS this the desired behaviour? Or e.g. email required? Confirm..
    r = client.post(
            '/admin/user',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "name": "new_test_user",
            })
        )
    assert r.status_code == 200
    assert r.json['username'] == 'new_test_user'
    assert r.json['is_admin'] == False
    assert r.json['role'] == 'user'
    assert r.json['email'] == None
    assert r.json['project_access'] == {}
    assert r.json['groups'] == []
    new_test_user = db_session.query(User).filter_by(username="new_test_user").one()
    assert new_test_user.username == 'new_test_user'
    assert new_test_user.is_admin == False
    assert new_test_user.email == None


def test_post_user_username_not_defined(client, admin_user, encoded_admin_jwt, db_session):
    """ POST /user: [create_user] username not defined """
    # TODO: What is the desired behaviour?
    # Right now 500 due to no username
    r = client.post(
            '/admin/user',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "email": "new_test_user@fake.com"
            })
        )
    assert True;


def test_post_user_already_exists(client, admin_user, encoded_admin_jwt, test_user_a, db_session):
    """ POST /user: [create_user] when user already exists """
    r = client.post(
            '/admin/user',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "name": "test_a",
            })
        )
    assert r.status_code == 400


def test_post_user_noauth(client):
    """ POST /user: [create_user] but without authorization """
    r = client.post('/admin/user')
    assert r.status_code == 401


# PUT /user/<username> tests

def test_put_user_username(client, admin_user, encoded_admin_jwt, db_session, test_user_a):
    """ PUT /user/<username>: [update_user] """
    r = client.put(
            '/admin/user/test_a',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "name": "test_a_updated",
                "role": "admin",
                "email": "test_a_updated@fake.com"
            })
        )
    assert r.status_code == 200
    assert r.json['username'] == 'test_a_updated'
    assert r.json['is_admin'] == True
    assert r.json['role'] == 'admin'
    assert r.json['email'] == 'test_a_updated@fake.com'
    assert r.json['project_access'] == {}
    assert r.json['groups'] == []
    updated_user = db_session.query(User).filter_by(username="test_a_updated").one()
    assert updated_user.username == 'test_a_updated'
    assert updated_user.is_admin == True
    assert updated_user.email == 'test_a_updated@fake.com'
    assert not db_session.query(User).filter_by(username="test_a").first()


def test_put_user_username_nonexistent(client, admin_user, encoded_admin_jwt, db_session):
    """ PUT /user/<username>: [update_user] username doesn't exist"""
    r = client.put(
            '/admin/user/test_nonexistent',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "name": "test_nonexistent_updated",
            })
        )
    assert r.status_code == 404
    assert not db_session.query(User).filter_by(username="test_nonexistent_updated").first()


def test_put_user_username_already_exists(client, admin_user, encoded_admin_jwt, db_session, test_user_a, test_user_b):
    """ PUT /user/<username>: [update_user] update to username that already exists """
    r = client.put(
            '/admin/user/test_a',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "name": "test_b",
            })
        )
    assert r.status_code == 400
    assert db_session.query(User).filter_by(username="test_a").one()
    assert db_session.query(User).filter_by(username="test_b").one()


def test_put_user_username_try_delete_username(client, admin_user, encoded_admin_jwt, db_session, test_user_a):
    """ PUT /user/<username>: [update_user] try to delete username"""
    r = client.put(
            '/admin/user/test_a',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "name": None,
            })
        )
    assert True
    # TODO: Don't know what desired behavior is;
    # actual behavior is currently a 500--see without_update_username


def test_put_user_username_try_delete_email(client, admin_user, encoded_admin_jwt, db_session, test_user_a):
    """ PUT /user/<username>: [update_user] try to delete email"""
    r = client.put(
            '/admin/user/test_a',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "email": None,
            })
        )
    assert True
    # TODO: Don't know what desired behavior is;
    # actual behavior is currently a 500--see without_update_username


def test_put_user_username_without_update_username(client, admin_user, encoded_admin_jwt, db_session, test_user_a):
    """ PUT /user/<username>: [update_user] update other fields but not username"""
    r = client.put(
            '/admin/user/test_a',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "email": "new_day_new_email@yay.com",
            })
        )
    assert True
    # TODO: Don't know what desired behavior is;
    # actual behavior is currently a 500 which has nothing to do with email
    # (it seems if username not updated then everything dies?)
    # TODO: Add this to that other story since culprit fn is same


def test_put_user_username_remove_admin_self(client, admin_user, encoded_admin_jwt, db_session):
    """ PUT /user/<username>: [update_user] what if admin un-admins self?"""
    r = client.put(
            '/admin/user/admin_user',
            headers={
                "Authorization": "Bearer " + encoded_admin_jwt,
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "role": "user",
            })
        )
    assert True
    # TODO: Don't know what desired behavior is;
    # actual behavior is currently a 500--see without_update_username


def test_put_user_username_noauth(client):
    """ PUT /user/<username>: [update_user] but without authorization """
    r = client.put('/admin/user/test_a')
    assert r.status_code == 401
