"""
Test the /credentials endpoint.
"""

import flask

from fence.models import (
    User,
    Client,
    IdentityProvider,
    GoogleServiceAccount,
    GoogleProxyGroup,
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
        app, oauth_client, db_session, cloud_manager):
    """
    Test that ``POST /credentials/google`` creates a new service
    account for the user if one doesn't exist.
    """
    _populate_test_identity(db_session, name=IdentityProvider.itrust)
    client_id = oauth_client['client_id']
    new_service_account = {
        'uniqueId': '987654321',
        'email': '987654321@test.com'
    }
    proxy_group_id = 'proxy_group_0'
    path = '/credentials/google/'

    # return new service account
    (
        cloud_manager.return_value
        .__enter__.return_value
        .create_service_account_for_proxy_group.return_value
    ) = new_service_account

    with app.test_client() as app_client:

        # set global client context
        flask.g.client_id = client_id

        service_accounts_before = (
            db_session
            .query(GoogleServiceAccount)
            .filter_by(client_id=client_id)
        ).count()

        # create a proxy group for user
        proxy_group = GoogleProxyGroup(
            id=proxy_group_id,
            email=proxy_group_id + "@test.com",
        )

        # get test user info
        user = (
            db_session
            .query(User)
            .filter_by(username='test')
            .first()
        )
        user.google_proxy_group_id = proxy_group.id

        db_session.add(user)
        db_session.add(proxy_group)
        db_session.commit()

        response = app_client.post(path)

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
        app, oauth_client, cloud_manager, db_session):
    """
    Test that ``POST /credentials/google`` return error when user
    has no proxy group and no service account.
    """
    client_id = oauth_client["client_id"]
    new_service_account = {
        "uniqueId": "987654321",
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

    with app.test_client() as app_client:

        # set global client context
        flask.g.client_id = client_id

        service_accounts_before = (
            db_session
            .query(GoogleServiceAccount)
            .filter_by(client_id=client_id)
        ).count()

        response = app_client.post(path, data=data)

        service_accounts_after = (
            db_session
            .query(GoogleServiceAccount)
            .filter_by(client_id=client_id)
        ).count()

        # make sure we created a new service account for the user's proxy
        # group and added it to the db
        assert (cloud_manager.return_value
                .__enter__.return_value
                .create_service_account_for_proxy_group).called is False
        assert service_accounts_after == service_accounts_before
        assert response.status_code == 404


def test_google_create_access_token_post(
        app, oauth_client, cloud_manager, db_session):
    """
    Test ``POST /credentials/google`` gets a new access key.
    """
    client_id = oauth_client['client_id']
    service_account_id = '123456789'
    proxy_group_id = 'proxy_group_0'
    path = '/credentials/google/'
    data = {}
    with app.test_client() as app_client:

        # set global client context
        flask.g.client_id = client_id

        # create a  proxy group for user
        proxy_group = GoogleProxyGroup(
            id=proxy_group_id,
            email=proxy_group_id + "@test.com"
        )

        # get test user info
        user = (
            db_session
            .query(User)
            .filter_by(username='test')
            .first()
        )
        user_id = user.id
        user.google_proxy_group_id = proxy_group.id

        db_session.add(proxy_group)

        # create a service account for client for user
        service_account = GoogleServiceAccount(
            google_unique_id=service_account_id,
            client_id=client_id,
            user_id=user_id,
            email=(client_id + '-' + str(user_id) + '@test.com')
        )
        db_session.add(user)
        db_session.add(service_account)
        db_session.commit()

        response = app_client.post(path, data=data)

        # check that the service account id was included in a
        # call to cloud_manager
        (
            cloud_manager.return_value
            .__enter__.return_value
            .get_access_key
        ).assert_called_with(service_account_id)

        assert response.status_code == 200


def test_google_delete_owned_access_token(
        app, client, oauth_client, cloud_manager, db_session):
    """
    Test ``DELETE /credentials/google``.
    """
    client_id = oauth_client["client_id"]
    service_account_key = "some_key_321"
    service_account_id = "123456789"
    proxy_group_id = "proxy_group_0"
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

    with app.test_client() as app_client:

        # set global client context
        flask.g.client_id = client_id

        # create a  proxy group for user
        proxy_group = GoogleProxyGroup(
            id=proxy_group_id,
            email=proxy_group_id + "@test.com"
        )

        # get test user info
        user = (
            db_session
            .query(User)
            .filter_by(username="test")
            .first()
        )
        user_id = user.id
        user.google_proxy_group_id = proxy_group.id

        db_session.add(proxy_group)

        # create a service account for client for user
        service_account = GoogleServiceAccount(
            google_unique_id=service_account_id,
            client_id=client_id,
            user_id=user_id,
            email=(client_id + "-" + str(user_id) + "@test.com")
        )
        db_session.add(user)
        db_session.add(service_account)
        db_session.commit()

        response = app_client.delete(path, data={})

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
        app, client, oauth_client, cloud_manager, db_session):
    """
    Test ``DELETE /credentials/google``.
    """
    client_id = oauth_client["client_id"]
    service_account_key = "some_key_321"
    proxy_group_id = "proxy_group_0"
    path = (
        "/credentials/google/" + service_account_key + "/"
    )

    with app.test_client() as app_client:

        # set global client context
        flask.g.client_id = client_id

        # create a  proxy group for user
        proxy_group = GoogleProxyGroup(
            id=proxy_group_id,
            email=proxy_group_id + "@test.com"
        )

        # get test user info
        user = (
            db_session
            .query(User)
            .filter_by(username="test")
            .first()
        )
        user_id = user.id
        user.google_proxy_group_id = proxy_group.id

        db_session.add(proxy_group)

        # create a service account for A DIFFERENT CLIENT
        client = Client(
            client_id="NOT_THIS_GUY", client_secret="a0987u23on192y",
            name="NOT_THIS_GUY",
        )
        service_account = GoogleServiceAccount(
            google_unique_id="123456789",
            client_id="NOT_THIS_GUY",
            user_id=user_id,
            email=("NOT_THIS_GUY" + "-" + str(user_id) + "@test.com")
        )
        db_session.add(user)
        db_session.add(client)
        db_session.add(service_account)
        db_session.commit()

        response = app_client.delete(path, data={})

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
        app, client, oauth_client, cloud_manager, db_session):
    """
    Test ``DELETE /credentials/google``.
    """
    client_id = oauth_client["client_id"]
    service_account_key = "some_key_321"
    service_account_id = "123456789"
    proxy_group_id = "proxy_group_0"
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

    with app.test_client() as app_client:

        # set global client context
        flask.g.client_id = client_id

        # create a  proxy group for user
        proxy_group = GoogleProxyGroup(
            id=proxy_group_id,
            email=proxy_group_id + "@test.com"
        )

        # get test user info
        user = (
            db_session
            .query(User)
            .filter_by(username="test")
            .first()
        )
        user_id = user.id
        user.google_proxy_group_id = proxy_group.id

        db_session.add(proxy_group)

        # create a service account for client for user
        service_account = GoogleServiceAccount(
            google_unique_id=service_account_id,
            client_id=client_id,
            user_id=user_id,
            email=(client_id + "-" + str(user_id) + "@test.com")
        )
        db_session.add(user)
        db_session.add(service_account)
        db_session.commit()

        response = app_client.delete(path, data={})

        # check that we didn't try to delete, since the key doesn't exist
        assert (cloud_manager.return_value
                .__enter__.return_value
                .delete_service_account_key).called is False

        assert response.status_code == 404
