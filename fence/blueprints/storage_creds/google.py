import flask
from flask_restful import Resource

from cirrus import GoogleCloudManager
from cirrus.config import config as cirrus_config

from fence.auth import require_auth_header
from fence.auth import current_token
from fence.resources.google.utils import get_service_account
from fence.resources.google.utils import create_google_access_key
from fence.resources.google.utils import (
    add_custom_service_account_key_expiration
)


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
            service_account = get_service_account(client_id, user_id)

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
        user_id = current_token["sub"]
        client_id = current_token.get("azp") or None
        proxy_group_id = (
            current_token.get('context', {})
            .get('user', {})
            .get('google', {})
            .get('proxy_group')
        )
        username = (
            current_token.get('context', {})
            .get('user', {})
            .get('name')
        )

        key, service_account = create_google_access_key(
            client_id, user_id, username, proxy_group_id)

        if client_id is None:
            self.handle_user_service_account_creds(key, service_account)

        return flask.jsonify(key)

    def handle_user_service_account_creds(self, key, service_account):
        """
        Add the service account creds for the user into our db. Actual
        Oauth Client SAs are handled separately. This function assigns
        the same expiration to the user's generated key but the mechanism
        for expiration uses our db instead of checking google directly.

        See fence-create scripting functions for expiration logic.

        The reason for this difference is due to the fact that fence itself
        uses the user's primary service account for url signing (in addition
        to the user themselves). Since the expirations are different, a
        different mechanism than the Client SAs was required.
        """
        # x days * 24 hr/day * 60 min/hr * 60 s/min = y seconds
        expires_in_seconds = (
            cirrus_config.SERVICE_KEY_EXPIRATION_IN_DAYS * 24 * 60 * 60
        )
        key_id = key.get('private_key_id')
        add_custom_service_account_key_expiration(
            key_id, service_account.id, expires=expires_in_seconds)


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
            service_account = get_service_account(client_id, user_id)

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
