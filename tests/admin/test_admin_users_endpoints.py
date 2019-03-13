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


@pytest.fixture(scope="function")
def test_user_d(db_session):
    """
    Test user for delete /user/<username>
    For delete-user tests you probably want to just use
    one of the load_*_user_data fixtures
    """
    user = db_session.query(User).filter_by(username="test_user_d").first()
    if not user:
        user = User(id=4242, username="test_user_d")
        db_session.add(user)
        db_session.commit()


@pytest.fixture(scope="function")
def load_non_google_user_data(db_session):
    """ Returns function to add general, non-Google user data to Fence db."""

    def fn_load_non_google_user_data():
        storage = StorageAccess(id=4220, user_id=4242)
        client = Client(
            client_id=4221,
            user_id=4242,
            issued_at=420,
            expires_at=42020,
            redirect_uri="dclient.com",
            grant_type="dgrant",
            response_type="dresponse",
            scope="dscope",
            name="dclientname",
            _allowed_scopes="dallscopes",
        )
        grp = Group(id=4240)
        usr_grp = UserToGroup(user_id=4242, group_id=4240)
        db_session.add_all([storage, client, grp, usr_grp])
        db_session.commit()

    return fn_load_non_google_user_data


@pytest.fixture(scope="function")
def load_google_specific_user_data(db_session, test_user_d):
    """ Returns function to add Google-specific user data to Fence db."""

    def fn_load_google_specific_user_data():
        gpg = GoogleProxyGroup(id="d_gpgid", email="d_gpg_email")

        gsak = GoogleServiceAccountKey(
            id=4201, key_id="d_sa_key", service_account_id=4202
        )
        gsa = GoogleServiceAccount(
            id=4202,
            google_unique_id="d_gui",
            user_id=4242,
            google_project_id="d_gpid",
            email="d_sa_email",
        )
        bkt = Bucket(id=4203)
        gbag = GoogleBucketAccessGroup(id=4204, bucket_id=4203, email="d_gbag_email")
        gpg_gbag = GoogleProxyGroupToGoogleBucketAccessGroup(
            id=4205, proxy_group_id="d_gpgid", access_group_id=4204
        )
        uga = UserGoogleAccount(id=4206, email="d_uga_email", user_id=4242)
        uga_pg = UserGoogleAccountToProxyGroup(
            user_google_account_id=4206, proxy_group_id="d_gpgid"
        )
        db_session.add_all([gpg, gsak, gsa, bkt, gbag, gpg_gbag, uga, uga_pg])

        user = db_session.query(User).filter_by(username="test_user_d").first()
        user.google_proxy_group_id = "d_gpgid"

        db_session.commit()

    return fn_load_google_specific_user_data

 
@pytest.fixture(scope="function")
def service_account_deletion_fails():
    """ Mock GCM such that it reports SA deletion failure """
    # fence.resources.admin, which you may have to call adm here, does
    # "from cirrus import GoogleCloudManager"
    # So you probably have to say, patch adm.GoogleCloudManager method delete_service_account
    # Oh so patch the entire adm.GoogleCloudMethod with a mock object that has a return_value set for delete_service_account
    mock = Mock()
    mock.SOMETHING.return_value = "SOMETHING"
    # Upd: Might not make sense to have this be a fixture.


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


# DELETE /users/<username> tests

@pytest.fixture(scope="function")
def assert_non_google_data_remained(db_session):
    def do_asserts():
        assert True #TODO
    return do_asserts

@pytest.fixture(scope="function")
def assert_non_google_data_deleted(db_session):
    def do_asserts():
        assert True #TODO
    return do_asserts


# NOTE: Currently these assert functions query by hard-coded primary keys.
# I could instead write utility fns to take any  user_id and count up all the
# associated SAs/keys/gpgs/etc, and then assert in the tests that these return the
# expected counts for our test_user_d. And this would usually be better code.
# But I think that for this particular testing use-case, hard-coding is better:

# (1) This WILL be sensitive to things like whether we accidentally set the 
#     ON DELETE to SET NULL instead of CASCADE (for example)--if we ref by
#     user_id, this wouldn't work, we'd get a false positive
# (2) This allows us to (much more easily) do things like check that the 
#     associated GBAG and Group rows (which have no user_id field but are linked
#     to a user via M-M tables) were NOT deleted;
# (3) In practice, I don't think we'll lose much by way of code 
#     reusability/extensibility. i.e. I don't foresee a need in future
#     to count up any-given-user's SAs/keys/other data as far as these tests
#     are concerned.

# TODO: Ask for opinions on this /\ if anybody ever has time

def assert_google_service_account_data_remained():
    """ Assert that test_user_d's Google SA and its key remain in Fence db."""
    sa = db_session.query(GoogleServiceAccount).filter_by(id=4202).all()
    assert len(sa) == 1
    sak = db_session.query(GoogleServiceAccountKey).filter_by(id=4201).all()
    assert len(sak) == 1

def assert_google_service_account_data_deleted():
    """ Assert that test_user_d's Google SA and its key are no longer in Fence db."""
    sa = db_session.query(GoogleServiceAccount).filter_by(id=4202).all()
    assert len(sa) == 0
    sak = db_session.query(GoogleServiceAccountKey).filter_by(id=4201).all()
    assert len(sak) == 0

# TODO: Write ^ equivalent for the rest of google data, the presence of which
# hinges on GPG deletion success.


# TODO: Parametrize
# TODO: Obviously need new fixtures
# endpoint returns response = jsonify(admin.delete_user(current_session, username))
def test_delete_user_username(
    #some_fixtures_here_idk_man,
    #client,
    #admin_user,
    #encoded_admin_jwt,
    db_session,
    #test_user_a,
    #idk,
    #but_definitely_the_below,
    load_non_google_user_data,
    load_google_specific_user_data,
    assert_non_google_data_deleted, #TODO Testing this haha
):
    """ DELETE /users/<username>: [delete_user]: TODO idk """
    """
    Case where Google is IDP and all as expected: Google data is in Fence and on Google,
    and all of the Google API calls via cirrus worked.
    Assert that all user data (Google and non-Google) cleared from Fence.
    """
    user = db_session.query(User).filter_by(username="test_user_d").first()
    if not user:
        user = User(id=4242, username="test_user_d")
        db_session.add(user)
        db_session.commit()
    assert_non_google_data_deleted()
    #assert_non_google_data_remained()#TODO no
    #r = client.delete(
    #    "/admin/users/test_user_d", headers={"Authorization": "Bearer " + encoded_admin_jwt}
    #)
    #assert r.status_code == 200  # TODO edit
    #assert r.json["username"] == "test_a"  # TODO delete


def test_delete_user_username_no_google():
    """
    Google is not being used as IDP, so GPG not found in Fence db;
    assert that non-Google Fence data is still deleted from Fence db.
      1. For this case, get_group won't return anything
    - Don't put any Google data in Fence db; just normal data
    - Only do assert that non Google data has been cleared
    """
    pass

def test_delete_user_username_gpg_only_in_google():
    """
    Google is IDP; GPG not found in Fence db for whatever reason,
    but found by cirrus in Google.
    Assert that non-Google Fence data is still deleted from Fence db
    and that Google data is deleted from Google.
    Except that last part isn't possible in a unit test.
      2. For this case, get_group will return a GPG
    - Don't put any Google data in Fence db; just normal data
    - Only do assert that non Google data has been cleared
    """
    pass

def test_delete_user_username_with_sa_deletion_fail():
    """
    Case where service account deletion fails in Google.
    Assert that SA and SA key data, and all other Google data,
    REMAINED in Fence;
    and all other non-Google data remained in Fence too.
    """
    pass

def test_delete_user_username_with_pg_deletion_fail():
    """
    Case where proxy group deletion fails in Google.
    Assert that SA and SA key data were deleted,
    but all other Google data present
    and all other non-Google data present too.
    """
    pass



"""
Right so I think the format will be 

def test_some_scenario(
    some fixtures here,
    load so and so data,
    load more data here,
    give me this assert function,
    give me this other assert function,
):
    with do_some_mock_patchy_thing_to_GCM as whatever:
        r = client.delete(blah)
    call_some_assert_fixture()
    call_another_assert_fixture()
#"""
"""
TODO: Probably your load data fixtures don't need to return functions. 
Now that you have decided not to parametrize scenarios.
Only the assert fixtures do
Wait hang on, why do the assert fixtures need to return functions hahaahah
You just need to pass them the db_session in an argument. NBD
Only needed this function-fixture business if you were going to parametrize
And I think parametrizing here would not save much redundancy
(all asserts already modular and data insertion actually quite simple)
but would make the asserts a lot harder to read.

@pytest.mark.parametrize(blah)
def test_all_the_cases(blah blah fixtures): 
  if case_1 or case_2 or case_3: 
    assertion 1
    assertion 4
  elif case_2 or case_4:
    assertion 2
    assertion 4
  else...etc etc

vs 

def test_case_1 (blah blah fixtures):
    with this_patch:
       call
    assertion 1
    assertion 4

def test_case_2 (blah):
    with this_other_patch:
       call
    assertion 2
    assertion 4
#"""
