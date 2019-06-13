"""
Test the /credentials endpoint.
"""
import pytest
from fence.models import (
    Client,
    IdentityProvider,
    GoogleServiceAccount,
    GoogleBucketAccessGroup,
)
from userdatamodel.user import (
    User,
    Project,
    AccessPrivilege,
    CloudProvider,
    Bucket,
    ProjectToBucket,
    StorageAccess,
)
from cdisutilstest.code.storage_client_mock import get_client

from fence.config import config

from unittest.mock import MagicMock, patch


def _populate_test_identity(session, **kwargs):
    """
    Add test information to db if it doesn't already exist
    for the IdentityProvider of the default test user
    """
    instance = session.query(IdentityProvider).filter_by(**kwargs).first()
    if not instance:
        instance = IdentityProvider(**kwargs)
        session.add(instance)
        session.commit()
        return instance


def test_google_access_token_new_service_account(
    app, client, oauth_client, db_session, encoded_creds_jwt, cloud_manager
):
    """
    Test that ``POST /credentials/google`` creates a new service
    account for the client if one doesn't exist.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    client_id = encoded_creds_jwt["client_id"]

    _populate_test_identity(db_session, name=IdentityProvider.itrust)
    new_service_account = {
        "uniqueId": "987654321",
        "email": "987654321@test.com",
        "projectId": "projectId-0",
    }
    path = "/credentials/google/"

    # return new service account
    (
        cloud_manager.return_value.__enter__.return_value.create_service_account_for_proxy_group.return_value
    ) = new_service_account

    service_accounts_before = (
        db_session.query(GoogleServiceAccount).filter_by(client_id=client_id)
    ).count()

    response = client.post(
        path, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    service_accounts_after = (
        db_session.query(GoogleServiceAccount).filter_by(client_id=client_id)
    ).count()

    # make sure we created a new service account for the user's proxy
    # group and added it to the db
    assert (
        cloud_manager.return_value.__enter__.return_value.create_service_account_for_proxy_group
    ).called
    assert service_accounts_after == service_accounts_before + 1
    assert response.status_code == 200


def test_google_access_token_new_proxy_group(
    app, client, oauth_client, cloud_manager, db_session, encoded_jwt_no_proxy_group
):
    """
    Test that ``POST /credentials/google`` creates new proxy group
    when one doesn't already exist
    """
    encoded_credentials_jwt = encoded_jwt_no_proxy_group["jwt"]
    client_id = encoded_jwt_no_proxy_group["client_id"]

    new_service_account = {
        "uniqueId": "987654321",
        "email": "987654321@test.com",
        "projectId": "1",
    }
    new_proxy_group = {"id": "123456789", "email": "987654321@test.com"}
    path = "/credentials/google/"
    data = {}

    # return new service account
    (
        cloud_manager.return_value.__enter__.return_value.create_service_account_for_proxy_group.return_value
    ) = new_service_account

    (
        cloud_manager.return_value.__enter__.return_value.create_proxy_group_for_user.return_value
    ) = new_proxy_group

    service_accounts_before = (
        db_session.query(GoogleServiceAccount).filter_by(client_id=client_id)
    ).count()

    response = client.post(
        path, data=data, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    service_accounts_after = (
        db_session.query(GoogleServiceAccount).filter_by(client_id=client_id)
    ).count()

    # make sure we created a new service account for the user's proxy
    # group and added it to the db
    assert (
        cloud_manager.return_value.__enter__.return_value.create_service_account_for_proxy_group
    ).called is True
    assert service_accounts_after == service_accounts_before + 1
    assert response.status_code == 200


def test_google_bucket_access_new_proxy_group(
    app,
    google_storage_client_mocker,
    client,
    cloud_manager,
    db_session,
    encoded_jwt_no_proxy_group,
    monkeypatch,
):
    monkeypatch.setitem(config, "MOCK_AUTH", False)

    user_id = encoded_jwt_no_proxy_group["user_id"]
    proj = Project(id=129, name="test_proj")
    ap = AccessPrivilege(
        user_id=user_id, project_id=proj.id, privilege=["write-storage"]
    )
    cloud = CloudProvider(id=129, name="google")
    bucket = Bucket(id=129, provider_id=cloud.id)
    gbag = GoogleBucketAccessGroup(
        id=129, bucket_id=bucket.id, email="gbag@email.com", privileges=["write"]
    )
    ptob = ProjectToBucket(id=129, project_id=proj.id, bucket_id=bucket.id)
    sa = StorageAccess(project_id=proj.id, provider_id=cloud.id)

    db_session.add(proj)
    db_session.add(ap)
    db_session.add(cloud)
    db_session.add(bucket)
    db_session.add(gbag)
    db_session.add(ptob)
    db_session.add(sa)
    db_session.commit()

    encoded_credentials_jwt = encoded_jwt_no_proxy_group["jwt"]

    new_service_account = {
        "uniqueId": "987654321",
        "email": "987654321@test.com",
        "projectId": "1",
    }
    new_proxy_group = {"id": "123456789", "email": "987654321@test.com"}
    path = "/credentials/google/"
    data = {}

    # return new service account
    (
        cloud_manager.return_value.__enter__.return_value.create_service_account_for_proxy_group.return_value
    ) = new_service_account

    (
        cloud_manager.return_value.__enter__.return_value.create_proxy_group_for_user.return_value
    ) = new_proxy_group

    response = client.post(
        path, data=data, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    assert google_storage_client_mocker.add_bucket_acl.called is True
    assert response.status_code == 200


def test_google_bucket_access_denied_new_proxy_group(
    app,
    google_storage_client_mocker,
    client,
    cloud_manager,
    db_session,
    encoded_jwt_no_proxy_group,
    monkeypatch,
):
    monkeypatch.setitem(config, "MOCK_AUTH", False)

    user_id = encoded_jwt_no_proxy_group["user_id"]
    proj = Project(id=129, name="test_proj")
    ap = AccessPrivilege(
        user_id=user_id, project_id=proj.id, privilege=["read-storage"]
    )
    cloud = CloudProvider(id=129, name="google")
    bucket = Bucket(id=129, provider_id=cloud.id)
    gbag = GoogleBucketAccessGroup(
        id=129, bucket_id=bucket.id, email="gbag@email.com", privileges=["write"]
    )
    ptob = ProjectToBucket(id=129, project_id=proj.id, bucket_id=bucket.id)
    sa = StorageAccess(project_id=proj.id, provider_id=cloud.id)

    db_session.add(proj)
    db_session.add(ap)
    db_session.add(cloud)
    db_session.add(bucket)
    db_session.add(gbag)
    db_session.add(ptob)
    db_session.add(sa)
    db_session.commit()

    encoded_credentials_jwt = encoded_jwt_no_proxy_group["jwt"]

    new_service_account = {
        "uniqueId": "987654321",
        "email": "987654321@test.com",
        "projectId": "1",
    }
    new_proxy_group = {"id": "123456789", "email": "987654321@test.com"}
    path = "/credentials/google/"
    data = {}

    # return new service account
    (
        cloud_manager.return_value.__enter__.return_value.create_service_account_for_proxy_group.return_value
    ) = new_service_account

    (
        cloud_manager.return_value.__enter__.return_value.create_proxy_group_for_user.return_value
    ) = new_proxy_group

    response = client.post(
        path, data=data, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    assert google_storage_client_mocker.delete_bucket_acl.called is True
    assert response.status_code == 200


def test_google_bucket_access_existing_proxy_group(
    app,
    google_storage_client_mocker,
    client,
    cloud_manager,
    db_session,
    encoded_creds_jwt,
    monkeypatch,
):
    monkeypatch.setitem(config, "MOCK_AUTH", False)

    user_id = encoded_creds_jwt["user_id"]
    client_id = encoded_creds_jwt["client_id"]

    service_account_id = "123456789"
    path = "/credentials/google/"

    proj = Project(id=129, name="test_proj")
    ap = AccessPrivilege(
        user_id=user_id, project_id=proj.id, privilege=["write-storage"]
    )
    cloud = CloudProvider(id=129, name="google")
    bucket = Bucket(id=129, provider_id=cloud.id)
    gbag = GoogleBucketAccessGroup(
        id=129, bucket_id=bucket.id, email="gbag@email.com", privileges=["write"]
    )
    ptob = ProjectToBucket(id=129, project_id=proj.id, bucket_id=bucket.id)
    sa = StorageAccess(project_id=proj.id, provider_id=cloud.id)
    service_account = GoogleServiceAccount(
        google_unique_id=service_account_id,
        client_id=client_id,
        user_id=user_id,
        email=(client_id + "-" + str(user_id) + "@test.com"),
        google_project_id="projectId-0",
    )

    db_session.add(service_account)
    db_session.commit()
    db_session.add(proj)
    db_session.add(ap)
    db_session.add(cloud)
    db_session.add(bucket)
    db_session.add(gbag)
    db_session.add(ptob)
    db_session.add(sa)
    db_session.add(service_account)
    db_session.commit()

    # make function return the service account we created and don't try to update db
    # since we already did it in the test
    mock = MagicMock()
    mock.return_value = service_account
    patch("fence.resources.google.utils.get_or_create_service_account", mock).start()
    patch("fence.resources.google.utils._update_service_account_db_entry", mock).start()

    encoded_credentials_jwt = encoded_creds_jwt["jwt"]

    path = "/credentials/google/"
    data = {}

    response = client.post(
        path, data=data, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    assert google_storage_client_mocker.add_bucket_acl.called is False
    assert response.status_code == 200


def test_google_create_access_token_post(
    app, client, oauth_client, cloud_manager, db_session, encoded_creds_jwt
):
    """
    Test ``POST /credentials/google`` gets a new access key.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    client_id = encoded_creds_jwt["client_id"]

    service_account_id = "123456789"
    service_account_email = client_id + "-" + str(user_id) + "@test.com"
    path = "/credentials/google/"
    data = {}

    # create a service account for client for user
    service_account = GoogleServiceAccount(
        google_unique_id=service_account_id,
        client_id=client_id,
        user_id=user_id,
        email=service_account_email,
        google_project_id="projectId-0",
    )
    db_session.add(service_account)
    db_session.commit()

    # make function return the service account we created and don't try to update db
    # since we already did it in the test
    mock = MagicMock()
    mock.return_value = service_account
    patch("fence.resources.google.utils.get_or_create_service_account", mock).start()
    patch("fence.resources.google.utils._update_service_account_db_entry", mock).start()

    response = client.post(
        path, data=data, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    # check that the service account id or email was included in a
    # call to cloud_manager
    args, kwargs = (
        cloud_manager.return_value.__enter__.return_value.get_access_key
    ).call_args
    combined = [arg for arg in args] + [value for key, value in kwargs.items()]
    assert service_account_id in combined or service_account_email in combined

    assert response.status_code == 200


def test_google_delete_owned_access_token(
    app, client, oauth_client, cloud_manager, db_session, encoded_creds_jwt
):
    """
    Test ``DELETE /credentials/google``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    client_id = encoded_creds_jwt["client_id"]

    service_account_key = "some_key_321"
    service_account_id = "123456789"
    service_account_email = client_id + "-" + str(user_id) + "@test.com"
    path = "/credentials/google/" + service_account_key

    def get_account_keys(*args, **kwargs):
        # Return the keys only if the correct account is given
        if args[0] == service_account_id or args[0] == service_account_email:
            # Return two keys, first one is NOT the one we're
            # requesting to delete
            return [
                {"name": "project/service_accounts/keys/over_9000"},
                {"name": "project/service_accounts/keys/" + service_account_key},
            ]
        else:
            return []

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account_keys_info.side_effect
    ) = get_account_keys

    # create a service account for client for user
    service_account = GoogleServiceAccount(
        google_unique_id=service_account_id,
        client_id=client_id,
        user_id=user_id,
        email=service_account_email,
        google_project_id="projectId-0",
    )
    db_session.add(service_account)
    db_session.commit()

    # make function return the service account we created and don't try to update db
    # since we already did it in the test
    mock = MagicMock()
    mock.return_value = service_account
    patch("fence.resources.google.utils.get_or_create_service_account", mock).start()
    patch("fence.resources.google.utils._update_service_account_db_entry", mock).start()

    response = client.delete(
        path, data={}, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    # check that the service account id was included in a call to
    # cloud_manager
    assert any(
        [
            str(mock_call)
            for mock_call in cloud_manager.mock_calls
            if service_account_id in str(mock_call)
            or service_account_email in str(mock_call)
        ]
    )
    assert response.status_code == 204

    # check that we actually requested to delete the correct service key
    args, kwargs = (
        cloud_manager.return_value.__enter__.return_value.delete_service_account_key
    ).call_args
    all_args = [arg for arg in args] + [value for key, value in kwargs.items()]
    assert service_account_id in all_args or service_account_email in all_args
    assert service_account_key in all_args


@pytest.mark.parametrize(
    "query_arg,valid_arg",
    [
        ("", False),
        ("?all=", False),
        ("?all=asdf", False),
        ("?all=false", False),
        ("?all=False", False),
        ("?all=true", True),
        ("?all=True", True),
    ],
)
def test_google_delete_all_owned_access_tokens(
    app,
    client,
    oauth_client,
    cloud_manager,
    db_session,
    encoded_creds_jwt,
    query_arg,
    valid_arg,
):
    """
    Test ``DELETE /credentials/google/*``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    client_id = encoded_creds_jwt["client_id"]

    service_account_key0 = "over_9000"
    service_account_key1 = "42"
    service_account_key2 = "one_MILLION_dollars"
    service_account_id = "123456789"
    service_account_email = client_id + "-" + str(user_id) + "@test.com"
    path = "/credentials/google/" + query_arg

    def get_account_keys(*args, **kwargs):
        # Return the keys only if the correct account is given
        if args[0] == service_account_id or args[0] == service_account_email:
            # Return multiple keys
            return [
                {"name": "project/service_accounts/keys/" + service_account_key0},
                {"name": "project/service_accounts/keys/" + service_account_key1},
                {"name": "project/service_accounts/keys/" + service_account_key2},
            ]
        else:
            return []

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account_keys_info.side_effect
    ) = get_account_keys

    # create a service account for client for user
    service_account = GoogleServiceAccount(
        google_unique_id=service_account_id,
        client_id=client_id,
        user_id=user_id,
        email=service_account_email,
        google_project_id="projectId-0",
    )
    db_session.add(service_account)
    db_session.commit()

    # make function return the service account we created and don't try to update db
    # since we already did it in the test
    mock = MagicMock()
    mock.return_value = service_account
    patch("fence.resources.google.utils.get_or_create_service_account", mock).start()
    patch("fence.resources.google.utils._update_service_account_db_entry", mock).start()

    response = client.delete(
        path, data={}, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    if valid_arg:
        # check that the service account id was included in a call to
        # cloud_manager
        assert any(
            [
                str(mock_call)
                for mock_call in cloud_manager.mock_calls
                if service_account_id in str(mock_call)
                or service_account_email in str(mock_call)
            ]
        )
        assert response.status_code == 204

        valid_calls = [
            (service_account_id, service_account_key0),
            (service_account_id, service_account_key1),
            (service_account_id, service_account_key2),
            (service_account_email, service_account_key0),
            (service_account_email, service_account_key1),
            (service_account_email, service_account_key2),
        ]
        actual_calls = []
        # check that we actually requested to delete the correct service key
        for (
            call
        ) in (
            cloud_manager.return_value.__enter__.return_value.delete_service_account_key.call_args_list
        ):
            args, kwargs = call
            actual_calls.append(args)

        assert set(actual_calls).issubset(valid_calls)
    else:
        # check that the service account id was NOT included in a call to
        # cloud_manager
        assert not any(
            [
                str(mock_call)
                for mock_call in cloud_manager.mock_calls
                if service_account_id in str(mock_call)
                or service_account_email in str(mock_call)
            ]
        )
        assert response.status_code != 204


def test_google_attempt_delete_unowned_access_token(
    app, client, oauth_client, cloud_manager, db_session, encoded_creds_jwt
):
    """
    Test ``DELETE /credentials/google``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]

    service_account_key = "some_key_321"
    path = "/credentials/google/" + service_account_key + "/"

    # create a service account for A DIFFERENT CLIENT
    client_entry = Client(
        client_id="NOT_THIS_GUY", client_secret="a0987u23on192y", name="NOT_THIS_GUY"
    )
    service_account = GoogleServiceAccount(
        google_unique_id="123456789",
        client_id="NOT_THIS_GUY",
        user_id=user_id,
        email=("NOT_THIS_GUY" + "-" + str(user_id) + "@test.com"),
        google_project_id="projectId-0",
    )
    db_session.add(client_entry)
    db_session.add(service_account)
    db_session.commit()

    # make function return the service account we created and don't try to update db
    # since we already did it in the test
    mock = MagicMock()
    mock.return_value = service_account
    patch("fence.resources.google.utils.get_or_create_service_account", mock).start()
    patch("fence.resources.google.utils._update_service_account_db_entry", mock).start()

    response = client.delete(
        path, data={}, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    # check that we didn't try to get key info or delete,
    # since the current user/client doesn't have the key
    assert (
        cloud_manager.return_value.__enter__.return_value.get_service_account_keys_info
    ).called is False

    assert (
        cloud_manager.return_value.__enter__.return_value.delete_service_account_key
    ).called is False

    assert response.status_code == 404


def test_google_delete_invalid_access_token(
    app, client, oauth_client, cloud_manager, db_session, encoded_creds_jwt
):
    """
    Test ``DELETE /credentials/google``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    client_id = encoded_creds_jwt["client_id"]

    service_account_key = "some_key_321"
    service_account_id = "123456789"
    path = "/credentials/google/" + service_account_key + "/"

    def get_account_keys(*args, **kwargs):
        # Return the keys only if the correct account is given
        if args[0] == service_account_id:
            # Return two keys, NEITHER are the key we want to delete
            return [
                {"name": "project/service_accounts/keys/voyager"},
                {"name": "project/service_accounts/keys/deep-space-nine"},
            ]
        else:
            return []

    (
        cloud_manager.return_value.__enter__.return_value.get_service_account_keys_info.side_effect
    ) = get_account_keys

    # create a service account for client for user
    service_account = GoogleServiceAccount(
        google_unique_id=service_account_id,
        client_id=client_id,
        user_id=user_id,
        email=(client_id + "-" + str(user_id) + "@test.com"),
        google_project_id="projectId-0",
    )
    db_session.add(service_account)
    db_session.commit()

    # make function return the service account we created and don't try to update db
    # since we already did it in the test
    mock = MagicMock()
    mock.return_value = service_account
    patch("fence.resources.google.utils.get_or_create_service_account", mock).start()
    patch("fence.resources.google.utils._update_service_account_db_entry", mock).start()

    response = client.delete(
        path, data={}, headers={"Authorization": "Bearer " + encoded_credentials_jwt}
    )

    # check that we didn't try to delete, since the key doesn't exist
    assert (
        cloud_manager.return_value.__enter__.return_value.delete_service_account_key
    ).called is False

    assert response.status_code == 404
