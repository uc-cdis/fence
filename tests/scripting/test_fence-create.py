import time
import mock

from unittest.mock import MagicMock, patch
import pytest

import cirrus
from cirrus.google_cloud.errors import GoogleAuthError
from userdatamodel.models import Group
from userdatamodel.driver import SQLAlchemyDriver

from fence.config import config
from fence.jwt.validate import validate_jwt
from fence.utils import create_client
from fence.models import (
    AccessPrivilege,
    Project,
    User,
    UserRefreshToken,
    Client,
    GoogleServiceAccount,
    UserServiceAccount,
    GoogleBucketAccessGroup,
    CloudProvider,
    Bucket,
    ServiceAccountToGoogleBucketAccessGroup,
    GoogleServiceAccountKey,
    StorageAccess,
)
from fence.scripting.fence_create import (
    delete_users,
    JWTCreator,
    create_client_action,
    delete_client_action,
    delete_expired_service_accounts,
    link_external_bucket,
    remove_expired_google_service_account_keys,
    verify_bucket_access_group,
    _verify_google_group_member,
    _verify_google_service_account_member,
    list_client_action,
    modify_client_action,
    create_projects,
    create_group,
)


ROOT_DIR = "./"


@pytest.fixture(autouse=True)
def mock_arborist(mock_arborist_requests):
    mock_arborist_requests()


def create_client_action_wrapper(
    to_test,
    db=None,
    client_name="exampleapp",
    username="exampleuser",
    urls=["https://betawebapp.example/fence", "https://webapp.example/fence"],
    grant_types=["authorization_code", "refresh_token", "implicit"],
    **kwargs,
):
    """
    Wraps create_client_action function and cleans up the client and user that
    are created in the database by create_client_action.
    """
    db = db or config["DB"]
    create_client_action(
        db,
        client=client_name,
        username=username,
        urls=urls,
        grant_types=grant_types,
        **kwargs,
    )
    to_test()
    driver = SQLAlchemyDriver(db)
    with driver.session as session:
        client = session.query(Client).filter_by(name=client_name).first()
        user = session.query(User).filter_by(username=username).first()
        if client is not None:
            session.delete(client)
        if user is not None:
            session.delete(user)
        session.commit()


def test_create_client_inits_default_allowed_scopes(db_session):
    """
    Test that calling create_client_action without allowed scopes still
    initializes the default allowed scopes for the client in the database.
    """
    client_name = "exampleapp"

    def to_test():
        saved_client = db_session.query(Client).filter_by(name=client_name).first()
        assert saved_client._allowed_scopes == " ".join(config["CLIENT_ALLOWED_SCOPES"])

    create_client_action_wrapper(
        to_test,
        client_name=client_name,
    )


def test_create_client_inits_passed_allowed_scopes(db_session):
    """
    Test that calling create_client_action with allowed scopes correctly
    initializes only the specified allowed scopes for the created client in the
    database.
    """
    client_name = "exampleapp"

    def to_test():
        saved_client = db_session.query(Client).filter_by(name=client_name).first()
        assert saved_client._allowed_scopes == "openid user data"

    create_client_action_wrapper(
        to_test,
        client_name=client_name,
        allowed_scopes=["openid", "user", "data"],
    )


def test_create_client_adds_openid_when_not_in_allowed_scopes(db_session):
    """
    Test that when the allowed scopes passed to create_client_action do not
    include the "openid" scope, that it still gets initialized as one of the
    client's allowed scopes.
    """
    client_name = "exampleapp"

    def to_test():
        saved_client = db_session.query(Client).filter_by(name=client_name).first()
        assert saved_client._allowed_scopes == "user data openid"

    create_client_action_wrapper(
        to_test,
        client_name=client_name,
        allowed_scopes=["user", "data"],
    )


def test_create_client_doesnt_create_client_with_invalid_scope(db_session):
    """
    Test that create_client_action does not create a client record in the
    database when one of the allowed scopes passed in is invalid.
    """
    client_name = "exampleapp"

    def to_test():
        client_after = db_session.query(Client).filter_by(name=client_name).all()
        assert len(client_after) == 0

    create_client_action_wrapper(
        to_test,
        client_name=client_name,
        allowed_scopes=["openid", "user", "data", "invalid_scope"],
    )


def test_client_delete(app, db_session, cloud_manager, test_user_a):
    """
    Test that the client delete function correctly cleans up the client's
    service accounts and the client themself.
    """
    client_name = "test123"
    client = Client(client_id=client_name, client_secret="secret", name=client_name)
    db_session.add(client)
    db_session.commit()

    client_service_account = GoogleServiceAccount(
        google_unique_id="jf09238ufposijf",
        client_id=client.client_id,
        user_id=test_user_a["user_id"],
        google_project_id="test",
        email="someemail@something.com",
    )
    db_session.add(client_service_account)
    db_session.commit()

    # empty return means success
    (
        cloud_manager.return_value.__enter__.return_value.delete_service_account.return_value
    ) = {}

    delete_client_action(config["DB"], client_name)

    client_after = db_session.query(Client).filter_by(name=client_name).all()
    client_service_account_after = (
        db_session.query(GoogleServiceAccount).filter_by(client_id=client.client_id)
    ).all()
    assert len(client_after) == 0
    assert len(client_service_account_after) == 0


def test_client_delete_error(app, db_session, cloud_manager, test_user_a):
    """
    Test that when Google gives us an error when deleting the service account,
    we don't remove it from the db.
    """
    client_name = "test123"
    client = Client(client_id=client_name, client_secret="secret", name=client_name)
    db_session.add(client)
    db_session.commit()

    client_service_account = GoogleServiceAccount(
        google_unique_id="jf09238ufposijf",
        client_id=client.client_id,
        user_id=test_user_a["user_id"],
        google_project_id="test",
        email="someemail@something.com",
    )
    db_session.add(client_service_account)
    db_session.commit()

    # error when deleting service account
    (
        cloud_manager.return_value.__enter__.return_value.delete_service_account.return_value
    ) = {"error": "something bad happened"}

    delete_client_action(config["DB"], client_name)

    client_after = db_session.query(Client).filter_by(name=client_name).all()
    client_service_account_after = (
        db_session.query(GoogleServiceAccount).filter_by(client_id=client.client_id)
    ).all()

    # make sure client is deleted but service account we couldn't delete stays
    assert len(client_after) == 0
    assert len(client_service_account_after) == 1


def test_delete_users(app, db_session, example_usernames):
    """
    Test the basic functionality of ``delete_users``.
    """
    for username in example_usernames:
        db_session.add(User(username=username))
        db_session.commit()
    # Delete all but the first user; check that the first one is still there
    # and the rest are gone.
    delete_users(config["DB"], example_usernames[1:])
    # Get the list of usernames for users that still exist.
    # (The `list(zip(...))` trick is to turn a list of 1-tuples into a
    # flattened list.)
    remaining_usernames = list(next(zip(*db_session.query(User.username).all())))
    assert example_usernames[0] in remaining_usernames
    for username in example_usernames[1:]:
        assert username not in remaining_usernames


def test_delete_user_with_access_privilege(app, db_session):
    user = User(username="test-user-with-privilege")
    project = Project(id=1, name="test-project")
    access_privilege = AccessPrivilege(user=user, privilege=["read"], project=project)
    db_session.add(user)
    db_session.add(project)
    db_session.add(access_privilege)
    db_session.commit()
    delete_users(config["DB"], [user.username])
    remaining_usernames = db_session.query(User.username).all()
    assert db_session.query(User).count() == 0, remaining_usernames


def test_create_user_access_token_with_no_found_user(
    app, db_session, kid, rsa_private_key
):
    user = User(username="test_user")
    db_session.add(user)
    jwt_creator = JWTCreator(
        config["DB"],
        config["BASE_URL"],
        kid=kid,
        username="other user",
        scopes="fence",
        expires_in=3600,
        private_key=rsa_private_key,
    )
    with pytest.raises(EnvironmentError):
        jwt_creator.create_access_token()


def test_create_user_refresh_token_with_no_found_user(
    app, db_session, kid, rsa_private_key
):
    user = User(username="test_user")
    db_session.add(user)
    jwt_creator = JWTCreator(
        config["DB"],
        config["BASE_URL"],
        kid=kid,
        username="other user",
        scopes="fence",
        expires_in=3600,
        private_key=rsa_private_key,
    )
    with pytest.raises(EnvironmentError):
        jwt_creator.create_refresh_token()


def test_create_user_access_token_bad_header(
    app, db_session, client, kid, rsa_private_key, oauth_client
):
    user = User(username="test_user")
    db_session.add(user)

    jwt_result = JWTCreator(
        config["DB"],
        config["BASE_URL"],
        kid=kid,
        username="test_user",
        scopes=["openid", "user"],
        expires_in=3600,
        private_key=rsa_private_key,
    ).create_access_token()
    r = client.get("/user", headers={"Authorization": "bear " + jwt_result.token})
    assert r.status_code == 401


def test_create_user_access_token(
    app, db_session, client, kid, rsa_private_key, oauth_client
):
    user = User(username="test_user")
    db_session.add(user)

    jwt_result = JWTCreator(
        config["DB"],
        config["BASE_URL"],
        kid=kid,
        username="test_user",
        scopes=["openid", "user"],
        expires_in=3600,
        private_key=rsa_private_key,
    ).create_access_token()
    r = client.get("/user", headers={"Authorization": "Bearer " + jwt_result.token})
    assert r.status_code == 200


def test_create_refresh_token_with_found_user(
    app, db_session, oauth_test_client, kid, rsa_private_key
):

    DB = config["DB"]
    username = "test_user"
    BASE_URL = config["BASE_URL"]
    scopes = "openid,user"
    expires_in = 3600

    user = User(username=username)
    db_session.add(user)

    user = db_session.query(User).filter_by(username=username).first()

    jwt_result = JWTCreator(
        DB,
        BASE_URL,
        kid=kid,
        username=username,
        scopes=scopes,
        expires_in=expires_in,
        private_key=rsa_private_key,
    ).create_refresh_token()

    refresh_token_response = oauth_test_client.refresh(
        refresh_token=jwt_result.token
    ).response

    ret_claims = validate_jwt(refresh_token_response.json["id_token"], {"openid"})
    assert jwt_result.claims["iss"] == ret_claims["iss"]
    assert jwt_result.claims["sub"] == ret_claims["sub"]
    assert jwt_result.claims["iat"] <= ret_claims["iat"]
    db_token = (
        db_session.query(UserRefreshToken)
        .filter_by(jti=jwt_result.claims["jti"])
        .first()
    )
    assert db_token is not None


def _setup_service_account_to_google_bucket_access_group(db_session):
    """
    Setup some testing data.
    """
    cloud_provider = CloudProvider(
        name="test_provider",
        endpoint="https://test.com",
        backend="test_backend",
        description="description",
        service="service",
    )
    db_session.add(cloud_provider)

    db_session.add(
        UserServiceAccount(
            google_unique_id="test_id1",
            email="test1@gmail.com",
            google_project_id="efewf444",
        )
    )
    db_session.add(
        UserServiceAccount(
            google_unique_id="test_id2",
            email="test2@gmail.com",
            google_project_id="edfwf444",
        )
    )
    db_session.commit()

    bucket1 = Bucket(name="test_bucket1", provider_id=cloud_provider.id)
    db_session.add(bucket1)
    db_session.commit()

    db_session.add(
        GoogleBucketAccessGroup(
            bucket_id=bucket1.id,
            email="testgroup1@gmail.com",
            privileges=["read-storage", "write-storage"],
        )
    )
    db_session.add(
        GoogleBucketAccessGroup(
            bucket_id=bucket1.id,
            email="testgroup2@gmail.com",
            privileges=["read-storage"],
        )
    )
    db_session.commit()


def test_delete_expired_service_accounts_with_one_fail_first(
    cloud_manager, app, db_session
):
    """
    Test the case that there is a failure of removing service account from google group
    """
    from googleapiclient.errors import HttpError
    import fence

    fence.settings = MagicMock()
    cirrus.config.update = MagicMock()
    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.side_effect = [
        HttpError(mock.Mock(status=403), bytes("Permission denied", "utf-8")),
        {},
    ]
    _setup_service_account_to_google_bucket_access_group(db_session)
    service_accounts = db_session.query(UserServiceAccount).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    current_time = int(time.time())

    # Add expired service account. This acccount is supposed to be deleted
    db_session.add(
        ServiceAccountToGoogleBucketAccessGroup(
            service_account_id=service_accounts[0].id,
            expires=current_time - 3600,
            access_group_id=google_bucket_access_grps[0].id,
        )
    )

    # Add non-expired service account.
    db_session.add(
        ServiceAccountToGoogleBucketAccessGroup(
            service_account_id=service_accounts[1].id,
            expires=current_time + 3600,
            access_group_id=google_bucket_access_grps[1].id,
        )
    )
    db_session.commit()

    # check database to make sure all the service accounts exist
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 2

    # call function to delete expired service account
    delete_expired_service_accounts(config["DB"])
    # check database again. Expect no service account is deleted
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 2


def test_delete_expired_service_accounts_with_one_fail_second(
    cloud_manager, app, db_session
):
    """
    Test the case that there is a failure of removing service account from google group
    """
    from googleapiclient.errors import HttpError
    import fence

    fence.settings = MagicMock()
    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.side_effect = [
        {},
        HttpError(mock.Mock(status=403), bytes("Permission denied", "utf-8")),
    ]
    _setup_service_account_to_google_bucket_access_group(db_session)
    service_accounts = db_session.query(UserServiceAccount).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    current_time = int(time.time())

    # Add two expired service account. They are both supposed to be deleted but
    # only one is deleted due to a raise exception
    service_account1 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id,
        expires=current_time - 3600,
        access_group_id=google_bucket_access_grps[0].id,
    )

    service_account2 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[1].id,
        expires=current_time - 3600,
        access_group_id=google_bucket_access_grps[1].id,
    )

    db_session.add(service_account1)
    db_session.add(service_account2)
    db_session.commit()

    # check database to make sure there are two records in DB
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 2

    # call function to delete expired service account
    delete_expired_service_accounts(config["DB"])
    # check database to make sure only the first one is deleted, the second one
    # still exists because of the raised exception
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 1
    assert records[0].id == service_account2.id


def test_delete_expired_service_accounts(cloud_manager, app, db_session):
    """
    Test deleting all expired service accounts
    """
    import fence

    fence.settings = MagicMock()
    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.return_value = (
        {}
    )
    _setup_service_account_to_google_bucket_access_group(db_session)
    service_accounts = db_session.query(UserServiceAccount).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    current_time = int(time.time())

    # Add 2 expired and 1 not expired accounts
    service_account1 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id,
        expires=current_time - 3600,
        access_group_id=google_bucket_access_grps[0].id,
    )
    service_account2 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[0].id,
        expires=current_time - 3600,
        access_group_id=google_bucket_access_grps[1].id,
    )
    service_account3 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_accounts[1].id,
        expires=current_time + 3600,
        access_group_id=google_bucket_access_grps[1].id,
    )

    db_session.add(service_account1)
    db_session.add(service_account2)
    db_session.add(service_account3)

    db_session.commit()

    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 3

    # call function to delete expired service account
    delete_expired_service_accounts(config["DB"])
    # check database. Expect 2 deleted
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 1
    assert records[0].id == service_account3.id


def test_delete_not_expired_service_account(app, db_session):
    """
    Test the case that there is no expired service account
    """
    import fence

    fence.settings = MagicMock()
    _setup_service_account_to_google_bucket_access_group(db_session)
    service_account = db_session.query(UserServiceAccount).first()
    google_bucket_access_grp1 = db_session.query(GoogleBucketAccessGroup).first()

    current_time = int(time.time())

    # Add non-expired service account
    service_account = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=service_account.id,
        expires=current_time + 3600,
        access_group_id=google_bucket_access_grp1.id,
    )
    db_session.add(service_account)
    db_session.commit()

    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 1

    # call function to delete expired service account
    delete_expired_service_accounts(config["DB"])
    # check db again to make sure the record still exists
    records = db_session.query(ServiceAccountToGoogleBucketAccessGroup).all()
    assert len(records) == 1


def test_verify_bucket_access_group_no_interested_accounts(
    app, cloud_manager, db_session, setup_test_data
):
    """
    Test that Google API returns no interested accounts
    """
    import fence

    fence.settings = MagicMock()
    (
        cloud_manager.return_value.__enter__.return_value.get_group_members.return_value
    ) = [
        {
            "kind": "admin#directory#member",
            "etag": "etag1",
            "id": "id1",
            "email": "test@gmail.com",
            "role": "role1",
            "type": "type",
        }
    ]

    fence.scripting.fence_create._verify_google_group_member = MagicMock()
    fence.scripting.fence_create._verify_google_service_account_member = MagicMock()
    verify_bucket_access_group(config["DB"])

    assert not fence.scripting.fence_create._verify_google_group_member.called
    assert not fence.scripting.fence_create._verify_google_service_account_member.called


def test_verify_bucket_access_group(app, cloud_manager, db_session, setup_test_data):
    """
    Test that Google API returns no interested accounts
    """
    import fence

    fence.settings = MagicMock()
    (
        cloud_manager.return_value.__enter__.return_value.get_group_members.return_value
    ) = [
        {
            "kind": "admin#directory#member",
            "etag": "etag1",
            "id": "id1",
            "email": "test1@gmail.com",
            "role": "role1",
            "type": "type",
        },
        {
            "kind": "admin#directory#member",
            "etag": "etag2",
            "id": "id2",
            "email": "test2@gmail.com",
            "role": "role2",
            "type": "GROUP",
        },
        {
            "kind": "admin#directory#member",
            "etag": "etag3",
            "id": "id3",
            "email": "test3@gmail.com",
            "role": "role3",
            "type": "GROUP",
        },
        {
            "kind": "admin#directory#member",
            "etag": "etag4",
            "id": "id4",
            "email": "test4@gmail.com",
            "role": "role4",
            "type": "USER",
        },
    ]

    fence.scripting.fence_create._verify_google_group_member = MagicMock()
    (fence.scripting.fence_create._verify_google_service_account_member) = MagicMock()
    verify_bucket_access_group(config["DB"])

    assert (fence.scripting.fence_create._verify_google_group_member.call_count) == 2
    assert (
        fence.scripting.fence_create._verify_google_service_account_member.call_count
    ) == 1


def test_verify_google_group_member(app, cloud_manager, db_session, setup_test_data):
    """
    Test that successfully deletes google group members which are not in Fence
    """
    access_group = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(email="access_grp_test1@gmail.com")
        .first()
    )
    member = {
        "kind": "admin#directory#member",
        "etag": "etag4",
        "id": "id4",
        "email": "test4@gmail.com",
        "role": "role4",
        "type": "GROUP",
    }

    _verify_google_group_member(db_session, access_group, member)
    assert (
        cloud_manager.return_value.__enter__.return_value.remove_member_from_group.called
    )


def test_verify_google_group_member_not_call_delete_operation(
    app, cloud_manager, db_session, setup_test_data
):
    """
    Test that does not delete google group members which are in Fence
    """
    access_group = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(email="access_grp_test1@gmail.com")
        .first()
    )
    member = {
        "kind": "admin#directory#member",
        "etag": "etag4",
        "id": "id4",
        "email": "group1@mail.com",
        "role": "role4",
        "type": "GROUP",
    }

    _verify_google_group_member(db_session, access_group, member)
    assert not (
        cloud_manager.return_value.__enter__.return_value.remove_member_from_group.called
    )


def test_verify_google_service_account_member_call_delete_operation(
    app, cloud_manager, db_session, setup_test_data
):
    """
    Test that deletes a google user member which is not in Fence
    """
    access_group = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(email="access_grp_test1@gmail.com")
        .first()
    )
    member = {
        "kind": "admin#directory#member",
        "etag": "etag4",
        "id": "id4",
        "email": "deleteting@mail.com",
        "role": "role4",
        "type": "USER",
    }

    _verify_google_service_account_member(db_session, access_group, member)
    assert (
        cloud_manager.return_value.__enter__.return_value.remove_member_from_group.called
    )


def test_verify_google_service_account_member_not_call_delete_operation(
    app, cloud_manager, db_session, setup_test_data
):
    """
    Test that does not delete a google user member which is in Fence
    """
    access_group = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(email="access_grp_test1@gmail.com")
        .first()
    )
    member = {
        "kind": "admin#directory#member",
        "etag": "etag4",
        "id": "id4",
        "email": "user1@gmail.com",
        "role": "role",
        "type": "USER",
    }

    _verify_google_service_account_member(db_session, access_group, member)
    assert not (
        cloud_manager.return_value.__enter__.return_value.remove_member_from_group.called
    )


def test_link_external_bucket(app, cloud_manager, db_session):

    (cloud_manager.return_value.__enter__.return_value.create_group.return_value) = {
        "email": "test_bucket_read_gbag@someemail.com"
    }

    bucket_count_before = db_session.query(Bucket).count()
    gbag_count_before = db_session.query(GoogleBucketAccessGroup).count()

    linked_gbag_email = link_external_bucket(config["DB"], "test_bucket")

    bucket_count_after = db_session.query(Bucket).count()
    gbag_count_after = db_session.query(GoogleBucketAccessGroup).count()

    assert cloud_manager.return_value.__enter__.return_value.create_group.called

    assert bucket_count_after == bucket_count_before + 1
    assert gbag_count_after == gbag_count_before + 1


def test_delete_expired_service_account_keys_for_user(
    cloud_manager, app, db_session, test_user_a
):
    """
    Test deleting all expired service account keys
    """
    import fence

    fence.settings = MagicMock()
    cloud_manager.return_value.__enter__.return_value.delete_service_account_key.return_value = (
        {}
    )

    current_time = int(time.time())

    service_account = GoogleServiceAccount(
        google_unique_id="1",
        user_id=test_user_a["user_id"],
        google_project_id="test",
        email="test@example.com",
    )
    db_session.add(service_account)
    db_session.commit()

    # Add 2 expired and 1 not expired accounts
    service_account_key1 = GoogleServiceAccountKey(
        key_id=1, service_account_id=service_account.id, expires=current_time - 3600
    )
    service_account_key2 = GoogleServiceAccountKey(
        key_id=2, service_account_id=service_account.id, expires=current_time - 3600
    )
    service_account_key3 = GoogleServiceAccountKey(
        key_id=3, service_account_id=service_account.id, expires=current_time + 3600
    )

    db_session.add(service_account_key1)
    db_session.add(service_account_key2)
    db_session.add(service_account_key3)
    db_session.commit()

    records = db_session.query(GoogleServiceAccountKey).all()
    assert len(records) == 3

    # call function to delete expired service account
    remove_expired_google_service_account_keys(config["DB"])
    # check database. Expect 2 deleted
    records = db_session.query(GoogleServiceAccountKey).all()
    assert len(records) == 1
    assert records[0].id == service_account_key3.id


def test_delete_expired_service_account_keys_for_client(
    cloud_manager, app, db_session, test_user_a, oauth_client
):
    """
    Test deleting all expired service account keys
    """
    import fence

    fence.settings = MagicMock()
    cloud_manager.return_value.__enter__.return_value.delete_service_account_key.return_value = (
        {}
    )

    current_time = int(time.time())

    client_service_account = GoogleServiceAccount(
        google_unique_id="1",
        user_id=test_user_a["user_id"],
        client_id=oauth_client["client_id"],
        google_project_id="test",
        email="test@example.com",
    )
    db_session.add(client_service_account)
    db_session.commit()

    # Add 2 expired and 1 not expired accounts
    service_account_key1 = GoogleServiceAccountKey(
        key_id=1,
        service_account_id=client_service_account.id,
        expires=current_time - 3600,
    )
    service_account_key2 = GoogleServiceAccountKey(
        key_id=2,
        service_account_id=client_service_account.id,
        expires=current_time - 3600,
    )
    service_account_key3 = GoogleServiceAccountKey(
        key_id=3,
        service_account_id=client_service_account.id,
        expires=current_time + 3600,
    )

    db_session.add(service_account_key1)
    db_session.add(service_account_key2)
    db_session.add(service_account_key3)
    db_session.commit()

    records = db_session.query(GoogleServiceAccountKey).all()
    assert len(records) == 3

    # call function to delete expired service account
    remove_expired_google_service_account_keys(config["DB"])
    # check database. Expect 2 deleted
    records = db_session.query(GoogleServiceAccountKey).all()
    assert len(records) == 1
    assert records[0].id == service_account_key3.id


def test_delete_expired_service_account_keys_both_user_and_client(
    cloud_manager, app, db_session, test_user_a, oauth_client
):
    """
    Test deleting all expired service account keys
    """
    import fence

    fence.settings = MagicMock()
    cloud_manager.return_value.__enter__.return_value.delete_service_account_key.return_value = (
        {}
    )

    current_time = int(time.time())

    service_account = GoogleServiceAccount(
        google_unique_id="1",
        user_id=test_user_a["user_id"],
        google_project_id="test",
        email="test@example.com",
    )
    client_service_account = GoogleServiceAccount(
        google_unique_id="1",
        user_id=test_user_a["user_id"],
        client_id=oauth_client["client_id"],
        google_project_id="test",
        email="test-client@example.com",
    )
    db_session.add(service_account)
    db_session.add(client_service_account)
    db_session.commit()

    # Add 2 expired and 1 not expired accounts
    service_account_key1 = GoogleServiceAccountKey(
        key_id=1, service_account_id=service_account.id, expires=current_time - 3600
    )
    service_account_key2 = GoogleServiceAccountKey(
        key_id=2,
        service_account_id=client_service_account.id,
        expires=current_time - 3600,
    )
    service_account_key3 = GoogleServiceAccountKey(
        key_id=3, service_account_id=service_account.id, expires=current_time + 3600
    )

    db_session.add(service_account_key1)
    db_session.add(service_account_key2)
    db_session.add(service_account_key3)
    db_session.commit()

    records = db_session.query(GoogleServiceAccountKey).all()
    assert len(records) == 3

    # call function to delete expired service account
    remove_expired_google_service_account_keys(config["DB"])
    # check database. Expect 2 deleted
    records = db_session.query(GoogleServiceAccountKey).all()
    assert len(records) == 1
    assert records[0].id == service_account_key3.id


def test_list_client_action(db_session, capsys):
    client_name = "test123"
    client = Client(client_id=client_name, client_secret="secret", name=client_name)
    db_session.add(client)
    db_session.commit()
    list_client_action(db_session)
    captured = capsys.readouterr()
    assert "'client_id': " + "'test123'" in captured[0]
    assert "'client_secret': " + "'secret'" in captured[0]
    assert "'name': " + "'test123'" in captured[0]


def test_modify_client_action(db_session):
    client_id = "testid"
    client_name = "test123"
    client = Client(client_id=client_id, client_secret="secret", name=client_name)
    db_session.add(client)
    db_session.commit()
    modify_client_action(
        db_session,
        client.name,
        set_auto_approve=True,
        name="test321",
        description="test client",
        urls=["test"],
    )
    list_client_action(db_session)
    assert client.auto_approve == True
    assert client.name == "test321"
    assert client.description == "test client"

    """
    TODO: Write test for unset_auto_approve modification of client action. As
    it stands it, seems as though this does not function properly in the case
    in which client is to be modified from auto_approve = True to
    auto_approve = False
    Is this a bug?
    """


def test_create_projects(db_session):
    # setup
    project_1_id = "123"
    project_1_name = "my-project-1"
    project_2_id = "456"
    project_2_name = "my-project-2"
    provider_id = "789"
    bucket_name = "my-bucket-2"

    cp = CloudProvider(
        id=provider_id,
        name=provider_id,
        endpoint="https://test.com",
        backend="test_backend",
        description="description",
        service="service",
    )
    db_session.add(cp)

    # only pre-create project 1
    p = Project(id=project_1_id, name=project_1_name)
    db_session.add(p)

    # only pre-create a StorageAccess for project 1
    sa = StorageAccess(project_id=project_1_id, provider_id=provider_id)
    db_session.add(sa)

    # only pre-create a Bucket for project 2
    b = Bucket(name=bucket_name, provider_id=provider_id)
    db_session.add(b)

    # test "fence-create create" projects creation
    data = {
        "projects": [
            {
                "id": project_1_id,
                "auth_id": "phs-project-1",
                "name": project_1_name,
                "storage_accesses": [{"name": provider_id, "buckets": ["my-bucket-1"]}],
            },
            {
                "id": project_2_id,
                "auth_id": "phs-project-2",
                "name": project_2_name,
                "storage_accesses": [{"name": provider_id, "buckets": [bucket_name]}],
            },
        ]
    }
    create_projects(db_session, data)

    projects_in_db = db_session.query(Project).all()
    assert projects_in_db, "no projects were created"
    assert len(projects_in_db) == len(data["projects"])
    project_names = {p.name for p in projects_in_db}
    assert project_1_name in project_names
    assert project_2_name in project_names


def test_create_group(db_session):
    # test "fence-create create" group creation without projects
    group_name = "test_group_1"
    data = {"groups": {group_name: {}}}
    create_group(db_session, data)
    groups_in_db = db_session.query(Group).filter(Group.name == group_name).all()
    assert groups_in_db, "no group was created"
    assert len(groups_in_db) == 1
    assert group_name == groups_in_db[0].name

    # test group creation with projects
    group_name = "test_group_2"
    data["groups"][group_name] = {
        "projects": [{"auth_id": "test_project_1", "privilege": "read"}]
    }
    create_group(db_session, data)
    groups_in_db = db_session.query(Group).filter(Group.name == group_name).all()
    assert groups_in_db, "no group was created"
    assert len(groups_in_db) == 1
    assert group_name == groups_in_db[0].name


def test_modify_client_action_modify_allowed_scopes(db_session):
    client_id = "testid"
    client_name = "test123"
    client = Client(
        client_id=client_id,
        client_secret="secret",
        name=client_name,
        _allowed_scopes="openid user data",
    )
    db_session.add(client)
    db_session.commit()
    modify_client_action(
        db_session,
        client.name,
        set_auto_approve=True,
        name="test321",
        description="test client",
        urls=["test"],
        allowed_scopes=["openid", "user", "test"],
    )
    list_client_action(db_session)
    assert client.auto_approve == True
    assert client.name == "test321"
    assert client.description == "test client"
    assert client._allowed_scopes == "openid user test"
    assert client.redirect_uris == ["test"]


def test_modify_client_action_modify_allowed_scopes_append_true(db_session):
    client_id = "testid"
    client_name = "test123"
    client = Client(
        client_id=client_id,
        client_secret="secret",
        name=client_name,
        _allowed_scopes="openid user data",
    )
    db_session.add(client)
    db_session.commit()
    modify_client_action(
        db_session,
        client.name,
        set_auto_approve=True,
        name="test321",
        description="test client",
        append=True,
        allowed_scopes=["new_scope", "new_scope_2", "new_scope_3"],
    )
    list_client_action(db_session)
    assert client.auto_approve == True
    assert client.name == "test321"
    assert client.description == "test client"
    assert (
        client._allowed_scopes == "openid user data new_scope new_scope_2 new_scope_3"
    )


def test_modify_client_action_modify_append_url(db_session):
    client_id = "testid"
    client_name = "test123"
    client = Client(
        client_id=client_id,
        client_secret="secret",
        name=client_name,
        _allowed_scopes="openid user data",
        redirect_uris="abcd",
    )
    db_session.add(client)
    db_session.commit()
    modify_client_action(
        db_session,
        client.name,
        set_auto_approve=True,
        name="test321",
        description="test client",
        urls=["test1", "test2", "test3"],
        append=True,
    )
    list_client_action(db_session)
    assert client.auto_approve == True
    assert client.name == "test321"
    assert client.description == "test client"
    assert client.redirect_uris == ["abcd", "test1", "test2", "test3"]
