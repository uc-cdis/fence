"""
Test the /credentials endpoint.
"""
from fence.models import (
    Client,
    IdentityProvider,
    GoogleServiceAccount,
)

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
        app, client, oauth_client, db_session,
        encoded_creds_jwt, cloud_manager):
    """
    Test that ``POST /credentials/google`` creates a new service
    account for the client if one doesn't exist.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    client_id = encoded_creds_jwt["client_id"]

    _populate_test_identity(db_session, name=IdentityProvider.itrust)
    new_service_account = {
        'uniqueId': '987654321',
        'email': '987654321@test.com',
        'projectId': 'projectId-0'
    }
    path = '/credentials/google/'

    # return new service account
    (
        cloud_manager.return_value
        .__enter__.return_value
        .create_service_account_for_proxy_group.return_value
    ) = new_service_account

    service_accounts_before = (
        db_session
        .query(GoogleServiceAccount)
        .filter_by(client_id=client_id)
    ).count()

    response = client.post(
        path,
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    service_accounts_after = (
        db_session
        .query(GoogleServiceAccount)
        .filter_by(client_id=client_id)
    ).count()

    # make sure we created a new service account for the user's proxy
    # group and added it to the db
    assert (
        cloud_manager.return_value
        .__enter__.return_value
        .create_service_account_for_proxy_group
    ).called
    assert service_accounts_after == service_accounts_before + 1
    assert response.status_code == 200


def test_google_access_token_no_proxy_group(
        app, client, oauth_client, cloud_manager, db_session,
        encoded_jwt_no_proxy_group):
    """
    Test that ``POST /credentials/google`` return error when user
    has no proxy group and no service account.
    """
    encoded_credentials_jwt = encoded_jwt_no_proxy_group["jwt"]
    client_id = encoded_jwt_no_proxy_group["client_id"]

    new_service_account = {
        "uniqueId": "987654321",
        "email": "987654321@test.com",
        "projectId": "1"
    }
    new_proxy_group = {
        "id": "123456789",
        "email": "987654321@test.com"
    }
    path = (
        "/credentials/google/"
    )
    data = {}

    # return new service account
    (
        cloud_manager.return_value
        .__enter__.return_value
        .create_service_account_for_proxy_group.return_value
    ) = new_service_account

    (
        cloud_manager.return_value
        .__enter__.return_value
        .create_proxy_group_for_user.return_value
    ) = new_proxy_group

    service_accounts_before = (
        db_session
        .query(GoogleServiceAccount)
        .filter_by(client_id=client_id)
    ).count()

    response = client.post(
        path, data=data,
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    service_accounts_after = (
        db_session
        .query(GoogleServiceAccount)
        .filter_by(client_id=client_id)
    ).count()

    # make sure we created a new service account for the user's proxy
    # group and added it to the db
    assert (cloud_manager.return_value
            .__enter__.return_value
            .create_service_account_for_proxy_group).called is True
    assert service_accounts_after == service_accounts_before + 1
    assert response.status_code == 200


def test_google_create_access_token_post(
        app, client, oauth_client, cloud_manager, db_session,
        encoded_creds_jwt):
    """
    Test ``POST /credentials/google`` gets a new access key.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    client_id = encoded_creds_jwt["client_id"]

    service_account_id = '123456789'
    path = '/credentials/google/'
    data = {}

    # create a service account for client for user
    service_account = GoogleServiceAccount(
        google_unique_id=service_account_id,
        client_id=client_id,
        user_id=user_id,
        email=(client_id + '-' + str(user_id) + '@test.com'),
        google_project_id='projectId-0'
    )
    db_session.add(service_account)
    db_session.commit()

    response = client.post(
        path, data=data,
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    # check that the service account id was included in a
    # call to cloud_manager
    (
        cloud_manager.return_value
        .__enter__.return_value
        .get_access_key
    ).assert_called_with(service_account_id)

    assert response.status_code == 200


def test_google_delete_owned_access_token(
        app, client, oauth_client, cloud_manager, db_session,
        encoded_creds_jwt):
    """
    Test ``DELETE /credentials/google``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    client_id = encoded_creds_jwt["client_id"]

    service_account_key = "some_key_321"
    service_account_id = "123456789"
    path = (
        "/credentials/google/" + service_account_key
    )

    def get_account_keys(*args, **kwargs):
        # Return the keys only if the correct account is given
        if args[0] == service_account_id:
            # Return two keys, first one is NOT the one we're
            # requesting to delete
            return [
                {
                    "name": "project/service_accounts/keys/over_9000"
                },
                {
                    "name":
                        "project/service_accounts/keys/" + service_account_key
                }
            ]
        else:
            return []

    (cloud_manager.return_value
     .__enter__.return_value
     .get_service_account_keys_info.side_effect) = get_account_keys

    # create a service account for client for user
    service_account = GoogleServiceAccount(
        google_unique_id=service_account_id,
        client_id=client_id,
        user_id=user_id,
        email=(client_id + "-" + str(user_id) + "@test.com"),
        google_project_id='projectId-0'
    )
    db_session.add(service_account)
    db_session.commit()

    response = client.delete(
        path, data={},
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    # check that the service account id was included in a call to
    # cloud_manager
    assert any([
        str(mock_call)
        for mock_call in cloud_manager.mock_calls
        if service_account_id in str(mock_call)
    ])
    assert response.status_code == 204

    # check that we actually requested to delete the correct service key
    (cloud_manager.return_value
     .__enter__.return_value
     .delete_service_account_key).assert_called_with(service_account_id,
                                                     service_account_key)


def test_google_attempt_delete_unowned_access_token(
        app, client, oauth_client, cloud_manager, db_session,
        encoded_creds_jwt):
    """
    Test ``DELETE /credentials/google``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]

    service_account_key = "some_key_321"
    path = (
        "/credentials/google/" + service_account_key + "/"
    )

    # create a service account for A DIFFERENT CLIENT
    client_entry = Client(
        client_id="NOT_THIS_GUY", client_secret="a0987u23on192y",
        name="NOT_THIS_GUY",
    )
    service_account = GoogleServiceAccount(
        google_unique_id="123456789",
        client_id="NOT_THIS_GUY",
        user_id=user_id,
        email=("NOT_THIS_GUY" + "-" + str(user_id) + "@test.com"),
        google_project_id='projectId-0'
    )
    db_session.add(client_entry)
    db_session.add(service_account)
    db_session.commit()

    response = client.delete(
        path, data={},
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    # check that we didn't try to get key info or delete,
    # since the current user/client doesn't have the key
    assert (cloud_manager.return_value
            .__enter__.return_value
            .get_service_account_keys_info).called is False

    assert (cloud_manager.return_value
            .__enter__.return_value
            .delete_service_account_key).called is False

    assert response.status_code == 404


def test_google_delete_invalid_access_token(
        app, client, oauth_client, cloud_manager, db_session,
        encoded_creds_jwt):
    """
    Test ``DELETE /credentials/google``.
    """
    encoded_credentials_jwt = encoded_creds_jwt["jwt"]
    user_id = encoded_creds_jwt["user_id"]
    client_id = encoded_creds_jwt["client_id"]

    service_account_key = "some_key_321"
    service_account_id = "123456789"
    path = (
        "/credentials/google/" + service_account_key + "/"
    )

    def get_account_keys(*args, **kwargs):
        # Return the keys only if the correct account is given
        if args[0] == service_account_id:
            # Return two keys, NEITHER are the key we want to delete
            return [
                {
                    "name": "project/service_accounts/keys/voyager"
                },
                {
                    "name": "project/service_accounts/keys/deep-space-nine"
                }
            ]
        else:
            return []

    (cloud_manager.return_value
     .__enter__.return_value
     .get_service_account_keys_info.side_effect) = get_account_keys

    # create a service account for client for user
    service_account = GoogleServiceAccount(
        google_unique_id=service_account_id,
        client_id=client_id,
        user_id=user_id,
        email=(client_id + "-" + str(user_id) + "@test.com"),
        google_project_id='projectId-0'
    )
    db_session.add(service_account)
    db_session.commit()

    response = client.delete(
        path, data={},
        headers={'Authorization': 'Bearer ' + encoded_credentials_jwt})

    # check that we didn't try to delete, since the key doesn't exist
    assert (cloud_manager.return_value
            .__enter__.return_value
            .delete_service_account_key).called is False

    assert response.status_code == 404
