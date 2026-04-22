from datetime import datetime, timedelta
import time
import mock

from unittest.mock import MagicMock, patch
import pytest

import gen3cirrus
from gen3cirrus.google_cloud.errors import GoogleAuthError
from userdatamodel.models import Group

from fence.config import config
from fence.errors import UserError
from fence.jwt.validate import validate_jwt
from fence.utils import create_client, get_SQLAlchemyDriver
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
    GoogleProxyGroup,
    ServiceAccountToGoogleBucketAccessGroup,
    GoogleProxyGroupToGoogleBucketAccessGroup,
    GoogleServiceAccountKey,
    StorageAccess,
    GA4GHVisaV1,
)
from fence.scripting.fence_create import (
    delete_users,
    JWTCreator,
    create_client_action,
    delete_client_action,
    delete_expired_clients_action,
    rotate_client_action,
    delete_expired_service_accounts,
    delete_expired_google_access,
    link_external_bucket,
    remove_expired_google_service_account_keys,
    verify_bucket_access_group,
    _verify_google_group_member,
    _verify_google_service_account_member,
    list_client_action,
    modify_client_action,
    create_projects,
    create_group,
    cleanup_expired_ga4gh_information,
)
from tests.dbgap_sync.conftest import add_visa_manually
from tests.utils import add_test_ras_user

ROOT_DIR = "./"


@pytest.fixture(autouse=True)
def mock_arborist(mock_arborist_requests):
    mock_arborist_requests()


def delete_client_if_exists(db, client_name, username=None):
    driver = get_SQLAlchemyDriver(db)
    with driver.session as session:
        clients = session.query(Client).filter_by(name=client_name).all()
        if clients:
            for client in clients:
                session.delete(client)
        if username:
            user = session.query(User).filter_by(username=username).first()
            if user is not None:
                session.delete(user)
        session.commit()


def create_client_action_wrapper(
    to_test,
    db=None,
    client_name="exampleapp",
    username="exampleuser",
    urls=["https://betawebapp.example/fence", "https://webapp.example/fence"],
    grant_types=["authorization_code", "refresh_token", "implicit"],
    expires_in=None,
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
        expires_in=expires_in,
        **kwargs,
    )
    to_test()
    delete_client_if_exists(db, client_name, username)


def test_create_client_inits_default_allowed_scopes(db_session):
    """
    Test that calling create_client_action without allowed scopes still
    initializes the default allowed scopes for the client in the database.
    """
    client_name = "exampleapp"

    def to_test():
        saved_client = db_session.query(Client).filter_by(name=client_name).first()
        assert saved_client.scope == " ".join(config["CLIENT_ALLOWED_SCOPES"])

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
        assert saved_client.scope == "openid user data"

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
        assert saved_client.scope == "user data openid"

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

    with pytest.raises(ValueError):
        create_client_action_wrapper(
            to_test,
            client_name=client_name,
            allowed_scopes=["openid", "user", "data", "invalid_scope"],
        )


def test_create_client_without_user_and_url(db_session):
    """
    Test that a client with the authorization_code grant cannot be created
    without providing a username or redirect URLs.
    """
    client_name = "client_with_client_credentials"
    grant_types = ["authorization_code", "client_credentials"]

    def to_test():
        client_after = db_session.query(Client).filter_by(name=client_name).all()
        assert len(client_after) == 0

    with pytest.raises(AssertionError):
        create_client_action_wrapper(
            to_test,
            client_name=client_name,
            username=None,
            urls=None,
            grant_types=grant_types,
        )


def test_create_client_with_client_credentials(db_session):
    """
    Test that a client with the client_credentials grant can be created
    without providing a username or redirect URLs.
    """
    client_name = "client_with_client_credentials"
    grant_types = ["client_credentials"]

    def to_test():
        saved_client = db_session.query(Client).filter_by(name=client_name).first()
        assert saved_client.grant_types == grant_types

    create_client_action_wrapper(
        to_test,
        client_name=client_name,
        username=None,
        urls=None,
        grant_types=grant_types,
    )


@pytest.mark.parametrize("expires_in", [None, 0, 1000, 0.5, -10, "not-valid"])
@pytest.mark.parametrize("grant_type", ["authorization_code", "client_credentials"])
def test_create_client_with_expiration(db_session, grant_type, expires_in):
    """
    Test that a client can be created with a valid expiration.
    """
    client_name = "client_with_expiration"
    grant_types = [grant_type]
    now = datetime.now()

    def to_test():
        saved_client = db_session.query(Client).filter_by(name=client_name).first()
        assert saved_client.grant_types == grant_types
        if not expires_in:
            assert saved_client.expires_at == 0
        else:
            expected_expires_at = (now + timedelta(days=expires_in)).timestamp()
            # allow up to 1 second variation to account for test execution
            assert saved_client.expires_at <= expected_expires_at + 1
            assert saved_client.expires_at >= expected_expires_at - 1

    if expires_in in [-10, "not-valid"]:
        with pytest.raises(UserError):
            create_client_action_wrapper(
                to_test,
                client_name=client_name,
                grant_types=grant_types,
                expires_in=expires_in,
            )
    else:
        create_client_action_wrapper(
            to_test,
            client_name=client_name,
            grant_types=grant_types,
            expires_in=expires_in,
        )


def test_create_client_duplicate_name(db_session):
    """
    Test that we can't create a new client with the same name as an existing client.
    """
    client_name = "non_unique_client_name"
    try:
        # successfully create a client
        create_client_action(
            config["DB"],
            client=client_name,
            username="exampleuser",
            urls=["https://localhost"],
            grant_types=["authorization_code"],
        )
        saved_client = db_session.query(Client).filter_by(name=client_name).first()
        assert saved_client.name == client_name

        # we should fail to create a 2nd client with the same name
        with pytest.raises(Exception, match=f"client {client_name} already exists"):
            create_client_action(
                config["DB"],
                client=client_name,
                username="exampleuser",
                urls=["https://localhost"],
                grant_types=["authorization_code"],
            )
    finally:
        delete_client_if_exists(config["DB"], client_name)


def test_client_delete(app, db_session, cloud_manager, test_user_a):
    """
    Test that the client delete function correctly cleans up the client's
    service accounts and the client themself.
    """
    client_name = "test123"
    client = Client(
        client_id=client_name,
        client_secret="secret",
        name=client_name,
        user=User(username="client_user"),
        redirect_uris="localhost",
    )
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
    client = Client(
        client_id=client_name,
        client_secret="secret",
        name=client_name,
        user=User(username="client_user"),
        redirect_uris=["localhost"],
    )
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


@pytest.mark.parametrize("post_to_slack", [False, True])
def test_client_delete_expired(app, db_session, cloud_manager, post_to_slack):
    """
    Test that the expired clients are correctly deleted along with their service accounts.
    Clients with "None" or "0" expiration do not expire.
    """
    # create a set of clients with different expirations
    user = User(username="client_user")
    for i, expires_in in enumerate([0.0000001, 0.000005, 1, 1000, None, 0]):
        client = Client(
            client_id=f"test_client_id_{i}",
            client_secret=f"secret_{i}",
            name=f"test_client_{i}",
            user=user,
            redirect_uris=["localhost", "other-uri"],
            expires_in=expires_in,
        )
        db_session.add(client)
    db_session.commit()

    # create a service account for one of the clients that will be removed
    client_service_account = GoogleServiceAccount(
        google_unique_id="jf09238ufposijf",
        client_id="test_client_id_0",
        user_id=user.id,
        google_project_id="test",
        email="someemail@something.com",
    )
    db_session.add(client_service_account)
    db_session.commit()

    # empty return means success
    cloud_manager.return_value.__enter__.return_value.delete_service_account.return_value = (
        {}
    )

    # wait 1 second for the clients to expire
    time.sleep(1)

    requests_mocker = mock.patch(
        "fence.scripting.fence_create.requests", new_callable=mock.Mock
    )
    with requests_mocker as mocked_requests:
        # delete the expired clients
        if not post_to_slack:
            delete_expired_clients_action(config["DB"])
        else:
            slack_webhook = "test-webhook"
            delete_expired_clients_action(
                config["DB"], slack_webhook=slack_webhook, warning_days=2
            )
            calls = mocked_requests.post.call_args_list
            assert (
                len(calls) == 2
            ), f"Expected 2 Slack webhook calls, but got {len(calls)}."

            # check the call about clients that have expired
            args, kwargs = calls[0]
            assert len(args) == 1 and args[0] == slack_webhook
            msg = kwargs.get("json", {}).get("attachments", [{}])[0].get("text")
            assert "test_client_0" in msg
            assert "test_client_1" in msg

            # check the call about clients that expire soon
            args, kwargs = calls[1]
            assert len(args) == 1 and args[0] == slack_webhook
            msg = kwargs.get("json", {}).get("attachments", [{}])[0].get("text")
            assert "test_client_2" in msg

    # make sure expired clients are deleted
    clients_after = db_session.query(Client).all()
    assert sorted([c.name for c in clients_after]) == [
        "test_client_2",
        "test_client_3",
        "test_client_4",
        "test_client_5",
    ]

    # make sure the service account for the expired client are deleted
    client_sa_after = (
        db_session.query(GoogleServiceAccount)
        .filter_by(client_id="test_client_id_0")
        .all()
    )
    assert len(client_sa_after) == 0


def test_client_rotate(db_session):
    """
    Create a client, rotate it and check that the 2 rows in the DB are identical except
    for the client ID, secret and expiration.
    """
    client_name = "client_abc"

    try:
        create_client_action(
            config["DB"],
            client=client_name,
            username="exampleuser",
            urls=["https://localhost"],
            grant_types=["authorization_code"],
            expires_in=30,
        )
        clients = db_session.query(Client).filter_by(name=client_name).all()
        assert len(clients) == 1
        assert clients[0].name == client_name

        rotate_client_action(config["DB"], client_name, 20)

        clients = db_session.query(Client).filter_by(name=client_name).all()
        assert len(clients) == 2

        assert clients[0].name == client_name
        assert clients[1].name == client_name
        for attr in [
            "user",
            "redirect_uris",
            "scope",
            "description",
            "auto_approve",
            "grant_types",
            "is_confidential",
            "token_endpoint_auth_method",
        ]:
            assert getattr(clients[0], attr) == getattr(
                clients[1], attr
            ), f"attribute '{attr}' differs"
        assert clients[0].client_id != clients[1].client_id
        assert clients[0].client_secret != clients[1].client_secret
        assert clients[0].expires_at != clients[1].expires_at
    finally:
        delete_client_if_exists(config["DB"], client_name)


def test_client_rotate_and_actions(db_session, capsys):
    """
    Check that listing, modifying or deleting a client (after rotating it) affects
    all of this client's rows in the DB.
    """
    client_name = "client_abc"

    # create a client and rotate the credentials twice
    url1 = "https://localhost"
    create_client_action(
        config["DB"],
        client=client_name,
        username="exampleuser",
        urls=[url1],
        grant_types=["authorization_code"],
        expires_in=30,
    )
    rotate_client_action(config["DB"], client_name, 20)
    rotate_client_action(config["DB"], client_name, 10)

    # this should result in 3 rows for this client in the DB
    clients = db_session.query(Client).filter_by(name=client_name).all()
    assert len(clients) == 3
    for i in range(3):
        assert clients[i].name == client_name

    # check that `list_client_action` lists all the rows
    capsys.readouterr()  # clear the buffer
    list_client_action(db_session)
    captured_logs = str(capsys.readouterr())
    assert captured_logs.count("'name\\': \\'client_abc\\'") == 3
    for i in range(3):
        assert (
            captured_logs.count(f"\\'client_id\\': \\'{clients[i].client_id}\\'") == 1
        )

    # check that `modify_client_action` updates all the rows
    description = "new description"
    url2 = "new url"
    modify_client_action(
        config["DB"], client_name, description=description, urls=[url2], append=True
    )
    clients = db_session.query(Client).filter_by(name=client_name).all()
    assert len(clients) == 3
    for i in range(3):
        assert clients[i].description == description
        assert clients[i].redirect_uris == [url1, url2]

    # check that `delete_client_action` deletes all the rows
    delete_client_action(config["DB"], client_name)
    clients = db_session.query(Client).filter_by(name=client_name).all()
    assert len(clients) == 0


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
    users = db_session.query(User).all()
    before_insert_count = len(users)
    user = User(username="test-user-with-privilege")
    project = Project(id=1, name="test-project")
    access_privilege = AccessPrivilege(user=user, privilege=["read"], project=project)
    db_session.add(user)
    db_session.add(project)
    db_session.add(access_privilege)
    db_session.commit()
    delete_users(config["DB"], [user.username])
    remaining_usernames = db_session.query(User.username).all()
    assert db_session.query(User).count() == before_insert_count, remaining_usernames


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
    client_id = "test-client"
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
        client_id=client_id,
    ).create_refresh_token()

    refresh_token_response = oauth_test_client.refresh(
        refresh_token=jwt_result.token
    ).response

    ret_claims = validate_jwt(
        refresh_token_response.json["id_token"],
        scope={"openid"},
    )
    assert jwt_result.claims["iss"] == ret_claims["iss"]
    assert jwt_result.claims["sub"] == ret_claims["sub"]
    assert jwt_result.claims["iat"] <= ret_claims["iat"]
    db_token = (
        db_session.query(UserRefreshToken)
        .filter_by(jti=jwt_result.claims["jti"])
        .first()
    )
    assert db_token is not None


def _setup_ga4gh_info(
    db_session, rsa_private_key, kid, access_1_expires=None, access_2_expires=None
):
    """
    Setup some testing data.

    Args:
        access_1_expires (str, optional): expiration for the Proxy Group ->
            Google Bucket Access Group for user 1, defaults to None
        access_2_expires (str, optional): expiration for the Proxy Group ->
            Google Bucket Access Group for user 2, defaults to None
    """
    test_user = add_test_ras_user(db_session)
    _, visa1 = add_visa_manually(
        db_session, test_user, rsa_private_key, kid, expires=access_1_expires
    )
    _, visa2 = add_visa_manually(
        db_session, test_user, rsa_private_key, kid, expires=access_2_expires
    )

    return {"ga4gh_visas": {"1": visa1.id, "2": visa2.id, "test_user": test_user}}


def _setup_google_access(db_session, access_1_expires=None, access_2_expires=None):
    """
    Setup some testing data.

    Args:
        access_1_expires (str, optional): expiration for the Proxy Group ->
            Google Bucket Access Group for user 1, defaults to None
        access_2_expires (str, optional): expiration for the Proxy Group ->
            Google Bucket Access Group for user 2, defaults to None
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

    gpg1 = GoogleProxyGroup(id=1, email="test1@gmail.com")
    gpg2 = GoogleProxyGroup(id=2, email="test2@gmail.com")
    db_session.add(gpg1)
    db_session.add(gpg2)
    db_session.commit()

    gbag1 = GoogleBucketAccessGroup(
        bucket_id=bucket1.id,
        email="testgroup1@gmail.com",
        privileges=["read-storage", "write-storage"],
    )
    gbag2 = GoogleBucketAccessGroup(
        bucket_id=bucket1.id,
        email="testgroup2@gmail.com",
        privileges=["read-storage"],
    )
    db_session.add(gbag1)
    db_session.add(gbag2)
    db_session.commit()

    db_session.add(
        GoogleProxyGroupToGoogleBucketAccessGroup(
            proxy_group_id=gpg1.id, access_group_id=gbag1.id, expires=access_1_expires
        )
    )
    db_session.add(
        GoogleProxyGroupToGoogleBucketAccessGroup(
            proxy_group_id=gpg2.id, access_group_id=gbag2.id, expires=access_2_expires
        )
    )
    db_session.commit()

    return {"google_proxy_group_ids": {"1": gpg1.id, "2": gpg2.id}}


def test_delete_expired_service_accounts_with_one_fail_first(
    cloud_manager, app, db_session
):
    """
    Test the case that there is a failure of removing service account from google group
    """
    from googleapiclient.errors import HttpError
    import fence

    gen3cirrus.config.update = MagicMock()
    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.side_effect = [
        HttpError(mock.Mock(status=403), bytes("Permission denied", "utf-8")),
        {},
    ]
    _setup_google_access(db_session)
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

    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.side_effect = [
        {},
        HttpError(mock.Mock(status=403), bytes("Permission denied", "utf-8")),
    ]
    _setup_google_access(db_session)
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

    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.return_value = (
        {}
    )
    _setup_google_access(db_session)
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

    _setup_google_access(db_session)
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


def test_delete_not_expired_google_access(app, db_session):
    """
    Test the case that there is no expired google access
    """
    import fence

    current_time = int(time.time())
    # 1 not expired, 2 not expired
    access_1_expires = current_time + 3600
    access_2_expires = current_time + 3600
    _setup_google_access(
        db_session, access_1_expires=access_1_expires, access_2_expires=access_2_expires
    )

    google_access = db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup).all()
    google_proxy_groups = db_session.query(GoogleProxyGroup).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    # check database to make sure all the service accounts exist
    pre_deletion_google_access_size = len(google_access)
    pre_deletion_google_proxy_groups_size = len(google_proxy_groups)
    pre_deletion_google_bucket_access_grps_size = len(google_bucket_access_grps)

    # call function to delete expired service account
    delete_expired_google_access(config["DB"])

    google_access = db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup).all()
    google_proxy_groups = db_session.query(GoogleProxyGroup).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    # check database again. Expect nothing is deleted
    assert len(google_access) == pre_deletion_google_access_size
    assert len(google_proxy_groups) == pre_deletion_google_proxy_groups_size
    assert len(google_bucket_access_grps) == pre_deletion_google_bucket_access_grps_size


def test_delete_not_specified_expiration_google_access(app, db_session):
    """
    Test the case that there is no expiration time specified in the db for google access
    In this case, we expect backwards compatible behavior, e.g. they are NOT removed
    """
    import fence

    current_time = int(time.time())
    access_1_expires = None
    access_2_expires = None
    _setup_google_access(
        db_session, access_1_expires=access_1_expires, access_2_expires=access_2_expires
    )

    google_access = db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup).all()
    google_proxy_groups = db_session.query(GoogleProxyGroup).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    # check database to make sure all the service accounts exist
    pre_deletion_google_access_size = len(google_access)
    pre_deletion_google_proxy_groups_size = len(google_proxy_groups)
    pre_deletion_google_bucket_access_grps_size = len(google_bucket_access_grps)

    # call function to delete expired service account
    delete_expired_google_access(config["DB"])

    google_access = db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup).all()
    google_proxy_groups = db_session.query(GoogleProxyGroup).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    # check database again. Expect nothing is deleted
    assert len(google_access) == pre_deletion_google_access_size
    assert len(google_proxy_groups) == pre_deletion_google_proxy_groups_size
    assert len(google_bucket_access_grps) == pre_deletion_google_bucket_access_grps_size


def test_delete_expired_google_access(cloud_manager, app, db_session):
    """
    Test deleting all expired service accounts
    """
    import fence

    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.return_value = (
        {}
    )

    current_time = int(time.time())
    # 1 expired, 2 not expired
    access_1_expires = current_time - 3600
    access_2_expires = current_time + 3600
    setup_results = _setup_google_access(
        db_session, access_1_expires=access_1_expires, access_2_expires=access_2_expires
    )

    google_access = db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup).all()
    google_proxy_groups = db_session.query(GoogleProxyGroup).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    # check database to make sure all the service accounts exist
    pre_deletion_google_access_size = len(google_access)
    pre_deletion_google_proxy_groups_size = len(google_proxy_groups)
    pre_deletion_google_bucket_access_grps_size = len(google_bucket_access_grps)

    # call function to delete expired service account
    delete_expired_google_access(config["DB"])

    google_access = db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup).all()
    google_proxy_groups = db_session.query(GoogleProxyGroup).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    # check database again. Expect 1 access is deleted - proxy group and gbag should be intact
    assert len(google_access) == pre_deletion_google_access_size - 1
    remaining_ids = [str(gpg_to_gbag.proxy_group_id) for gpg_to_gbag in google_access]

    # b/c expired
    assert str(setup_results["google_proxy_group_ids"]["1"]) not in remaining_ids

    # b/c not expired
    assert str(setup_results["google_proxy_group_ids"]["2"]) in remaining_ids

    assert len(google_proxy_groups) == pre_deletion_google_proxy_groups_size
    assert len(google_bucket_access_grps) == pre_deletion_google_bucket_access_grps_size


def test_delete_expired_google_access_with_one_fail_first(
    cloud_manager, app, db_session
):
    """
    Test the case that there is a failure of removing from google group in GCP.
    In this case, we still want the expired record to exist in the db so we can try to
    remove it again.
    """
    from googleapiclient.errors import HttpError
    import fence

    gen3cirrus.config.update = MagicMock()
    cloud_manager.return_value.__enter__.return_value.remove_member_from_group.side_effect = [
        HttpError(mock.Mock(status=403), bytes("Permission denied", "utf-8")),
        {},
    ]

    current_time = int(time.time())
    # 1 expired, 2 not expired
    access_1_expires = current_time - 3600
    access_2_expires = current_time + 3600
    _setup_google_access(
        db_session, access_1_expires=access_1_expires, access_2_expires=access_2_expires
    )

    google_access = db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup).all()
    google_proxy_groups = db_session.query(GoogleProxyGroup).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    # check database to make sure all the service accounts exist
    pre_deletion_google_access_size = len(google_access)
    pre_deletion_google_proxy_groups_size = len(google_proxy_groups)
    pre_deletion_google_bucket_access_grps_size = len(google_bucket_access_grps)

    # call function to delete expired service account
    delete_expired_google_access(config["DB"])

    google_access = db_session.query(GoogleProxyGroupToGoogleBucketAccessGroup).all()
    google_proxy_groups = db_session.query(GoogleProxyGroup).all()
    google_bucket_access_grps = db_session.query(GoogleBucketAccessGroup).all()

    # check database again. Expect nothing is deleted
    assert len(google_access) == pre_deletion_google_access_size
    assert len(google_proxy_groups) == pre_deletion_google_proxy_groups_size
    assert len(google_bucket_access_grps) == pre_deletion_google_bucket_access_grps_size


def test_cleanup_expired_ga4gh_information(app, db_session, rsa_private_key, kid):
    """
    Test removal of expired ga4gh info
    """
    import fence

    current_time = int(time.time())
    # 1 expired, 2 not expired
    access_1_expires = current_time - 3600
    access_2_expires = current_time + 3600
    setup_results = _setup_ga4gh_info(
        db_session,
        rsa_private_key,
        kid,
        access_1_expires=access_1_expires,
        access_2_expires=access_2_expires,
    )

    ga4gh_visas = db_session.query(GA4GHVisaV1).all()

    # check database to make sure all the service accounts exist
    pre_deletion_ga4gh_visas_size = len(ga4gh_visas)

    # call function to delete expired service account
    cleanup_expired_ga4gh_information(config["DB"])

    ga4gh_visas = db_session.query(GA4GHVisaV1).all()

    # check database again. Expect 1 access is deleted - proxy group and gbag should be intact
    assert len(ga4gh_visas) == pre_deletion_ga4gh_visas_size - 1
    remaining_ids = [str(item.id) for item in ga4gh_visas]

    # b/c expired
    assert str(setup_results["ga4gh_visas"]["1"]) not in remaining_ids

    # b/c not expired
    assert str(setup_results["ga4gh_visas"]["2"]) in remaining_ids


def test_verify_bucket_access_group_no_interested_accounts(
    app, cloud_manager, db_session, setup_test_data
):
    """
    Test that Google API returns no interested accounts
    """
    import fence

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
    client = Client(
        client_id=client_name,
        client_secret="secret",
        name=client_name,
        user=User(username="client_user"),
        redirect_uris=["localhost"],
    )
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
    client = Client(
        client_id=client_id,
        client_secret="secret",
        name=client_name,
        user=User(username="client_user"),
        redirect_uris=["localhost"],
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
        client_secret="secret",  # pragma: allowlist secret
        name=client_name,
        allowed_scopes="openid user data",
        user=User(username="client_user"),
        redirect_uris=["localhost"],
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
    assert client.scope == "openid user test"
    assert client.redirect_uris == ["test"]


def test_modify_client_action_modify_allowed_scopes_append_true(db_session):
    client_id = "testid"
    client_name = "test123"
    client = Client(
        client_id=client_id,
        client_secret="secret",  # pragma: allowlist secret
        name=client_name,
        allowed_scopes="openid user data",
        user=User(username="client_user"),
        redirect_uris=["localhost"],
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
    assert client.scope == "openid user data new_scope new_scope_2 new_scope_3"


def test_modify_client_action_modify_append_url(db_session):
    client_id = "testid"
    client_name = "test123"
    client = Client(
        client_id=client_id,
        client_secret="secret",  # pragma: allowlist secret
        name=client_name,
        allowed_scopes="openid user data",
        user=User(username="client_user"),
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


@pytest.mark.parametrize("expires_in", [None, 0, 1000, 0.5, -10, "not-valid"])
@pytest.mark.parametrize("existing_expiration", [True, False])
def test_modify_client_expiration(db_session, expires_in, existing_expiration):
    """
    Test that a client can be modified with a valid expiration.
    """
    # create a client
    client_name = "test_client"
    client = Client(
        client_id="test_client_id",
        client_secret="secret",
        name=client_name,
        user=User(username="client_user"),
        redirect_uris="localhost",
        expires_in=(2 if existing_expiration else None),
    )
    db_session.add(client)
    db_session.commit()
    original_expires_at = client.expires_at

    # modify the client's expiration
    now = datetime.now()
    if expires_in in [-10, "not-valid"]:
        with pytest.raises(UserError):
            modify_client_action(
                DB=db_session, client=client_name, expires_in=expires_in
            )
    else:
        modify_client_action(DB=db_session, client=client_name, expires_in=expires_in)

        # make sure the expiration was updated if necessary
        if not expires_in:
            assert client.expires_at == original_expires_at
        else:
            expected_expires_at = (now + timedelta(days=expires_in)).timestamp()
            # allow up to 1 second variation to account for test execution
            assert client.expires_at <= expected_expires_at + 1
            assert client.expires_at >= expected_expires_at - 1
