from cirrus import GoogleCloudManager
from cirrus.google_cloud import get_valid_service_account_id_for_client

from flask_sqlalchemy_session import current_session
import flask
from flask_restful import Resource

from fence.auth import require_auth_header
from fence.auth import current_token
from fence.models import GoogleServiceAccount


class GoogleCredentialsList(Resource):
    """
    For ``/credentials/google`` endpoint.
    """

    @require_auth_header({'credentials'})
    def get(self):
        """
        List access keys for user

        **Example:**
        .. code-block:: http

               POST /credentials/apis/ HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        Info from Google API /serviceAccounts/<account>/keys endpoint
        TODO: In the future we should probably add in our expiration time, when
              we start monitoring and deleting after x amount of time

        .. code-block:: JavaScript

            {
                "access_keys":
                [
                    {
                        "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
                        "validBeforeTime": string,
                        "name": string,
                        "validAfterTime": string,
                    },
                    ...
                ]
            }

        """
        client_id = current_token.get("azp") or None
        user_id = current_token["sub"]

        with GoogleCloudManager() as g_cloud_manager:
            service_account = _get_google_service_account_for_client(
                g_cloud_manager, client_id, user_id)

            if service_account:
                keys = g_cloud_manager.get_service_account_keys_info(
                    service_account.google_unique_id)
                result = {'access_keys': keys}
            else:
                result = {'access_keys': []}

        return flask.jsonify(result)

    @require_auth_header({'credentials'})
    def post(self):
        """
        Generate a keypair for user

        **Example:**
        .. code-block:: http

               POST /credentials/cdis/?expires_in=3600 HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        (JSON key in Google Credentials File format)

        .. code-block:: JavaScript

            {
                "type": "service_account",
                "project_id": "project-id",
                "private_key_id": "some_number",
                "private_key": "-----BEGIN PRIVATE KEY-----\n....
                =\n-----END PRIVATE KEY-----\n",
                "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
                "client_id": "...",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com"
            }
        """
        client_id = current_token.get("azp") or None
        user_id = current_token["sub"]

        with GoogleCloudManager() as g_cloud:
            client_id = current_token.get("azp") or None
            key = _get_google_access_key_for_client(
                g_cloud, client_id, user_id)
        return flask.jsonify(key)


class GoogleCredentials(Resource):

    @require_auth_header({'credentials'})
    def delete(self, access_key):
        """
        .. http:get: /google/(string: access_key)
        Delete a keypair for user

        :param access_key: existing access key that belongs to this user

        :statuscode 204 Success
        :statuscode 403 Forbidden to delete access key
        :statuscode 404 Access key doesn't exist
        """
        user_id = current_token["sub"]

        with GoogleCloudManager() as g_cloud:
            client_id = current_token.get("azp") or None
            service_account = _get_google_service_account_for_client(
                g_cloud, client_id, user_id)

            if service_account:
                keys_for_account = (
                    g_cloud.get_service_account_keys_info(
                        service_account.google_unique_id)
                )

                # Only delete the key if is owned by current client's SA
                all_client_keys = [
                    key['name'].split('/')[-1]
                    for key in keys_for_account
                ]
                if access_key in all_client_keys:
                    g_cloud.delete_service_account_key(
                        service_account.google_unique_id, access_key)
                else:
                    flask.abort(
                        404, 'Could not delete key ' + access_key +
                        '. Not found for current user.')
            else:
                flask.abort(
                    404, 'Could not find service account for current user.')

        return '', 204


def _get_google_access_key_for_client(g_cloud_manager, client_id, user_id):
    """
    Return an access key for current user and client.

    Args:
        g_cloud_manager (cirrus.GoogleCloudManager): instance of
        cloud manager to use

    Returns:

        JSON key in Google Credentials File format:

        .. code-block:: JavaScript

            {
                "type": "service_account",
                "project_id": "project-id",
                "private_key_id": "some_number",
                "private_key": "-----BEGIN PRIVATE KEY-----\n....
                =\n-----END PRIVATE KEY-----\n",
                "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
                "client_id": "...",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com"
            }
    """
    service_account = _get_google_service_account_for_client(
        g_cloud_manager, client_id, user_id)

    if not service_account:
        if client_id:
            service_account = _create_google_service_account_for_client(
                g_cloud_manager, client_id, user_id)
        else:
            # error about requiring client id in azp field of token
            flask.abort(
                404, 'Could not find client id in `azp` field of token. '
                'Cannot create Google key.')

    key = g_cloud_manager.get_access_key(service_account.google_unique_id)
    return key


def _get_google_service_account_for_client(
        g_cloud_manager, client_id, user_id):
    """
    Return the service account (from Fence db) for current client.

    Get the service account that is associated with the current client
    for this user. There will be a single service account per client.

    Args:
        g_cloud_manager (cirrus.GoogleCloudManager): instance of
        cloud manager to use

    Returns:
        fence.models.GoogleServiceAccount: Client's service account
    """
    service_account = (
        current_session
        .query(GoogleServiceAccount)
        .filter_by(client_id=client_id,
                   user_id=user_id)
        .first()
    )

    return service_account


def _create_google_service_account_for_client(
        g_cloud_manager, client_id, user_id):
    """
    Create a Google Service account for the current client and user.

    Args:
        g_cloud_manager (cirrus.GoogleCloudManager): instance of
        cloud manager to use

    Returns:
        fence.models.GoogleServiceAccount: New service account
    """
    proxy_group_id = (
        current_token.get('context', {})
        .get('user', {})
        .get('google', {})
        .get('proxy_group')
    )

    if proxy_group_id:
        service_account_id = get_valid_service_account_id_for_client(
            client_id, user_id)

        new_service_account = (
            g_cloud_manager.create_service_account_for_proxy_group(
                proxy_group_id, account_id=service_account_id)
        )

        service_account = GoogleServiceAccount(
            google_unique_id=new_service_account['uniqueId'],
            client_id=client_id,
            user_id=user_id,
            email=new_service_account['email']
        )

        current_session.add(service_account)
        current_session.commit()

        return service_account

    else:
        flask.abort(
            404, 'Could not find Google proxy group for current user in the '
            'given token.')
