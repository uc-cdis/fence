from fence.auth import login_required
from fence.data_model.models import GoogleServiceAccount
from fence.data_model.models import GoogleProxyGroup
import flask
from flask import current_app as capp
from flask import g, request, jsonify
from flask import abort
from flask_sqlalchemy_session import current_session

from cirrus import GoogleCloudManager
from fence.resources.storage.cdis_jwt import create_refresh_token,\
    revoke_refresh_token, create_access_token

blueprint = flask.Blueprint('credentials', __name__)

ALL_RESOURCES = {
    "/cdis": "access to CDIS APIs",
    "/ceph": "access to Ceph storage",
    "/cleversafe": "access to cleversafe storage",
    "/aws-s3": "access to AWS S3 storage",
    "/google": "access to Google storage"
}


@blueprint.route('/', methods=['GET'])
@login_required({'credentials'})
def list_sources():
    '''
    List different resources user can have credentials

    **Example:**
    .. code-block:: http

           GET /credentials/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json

    .. code-block:: JavaScript

        {
            "/cdis": "access to CDIS APIs",
            "/ceph": "access to Ceph storage",
            "/cleversafe": "access to cleversafe storage",
            "/aws-s3", "access to AWS S3 storage"
            "/google", "access to Google Cloud storage"
        }
    '''
    services = capp.config.get('STORAGES', [])
    return jsonify({k: ALL_RESOURCES[k] for k in services})


@blueprint.route('/<backend>/', methods=['GET'])
@login_required({'credentials'})
def list_credentials(backend):
    '''
    List all existing credentials (keypairs/tokens) for user

    **Example:**
    .. code-block:: http

           POST /credentials/apis/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json

    .. code-block:: JavaScript

        [
            {
                'access_key': '8DGW9LyC0D4nByoWo6pp',
            }
        ]

    '''
    if backend == 'cdis':
        result = cdis_list_keypairs(g.user, current_session)
    elif backend == 'google':
        with GoogleCloudManager() as g_cloud_manager:
            service_account = _get_google_service_account_for_client(g_cloud_manager)

            if service_account:
                result = g_cloud_manager.get_service_account_keys_info(service_account.google_unique_id)
            else:
                result = {}
    else:
        result = capp.storage_manager.list_keypairs(backend, g.user)

    return jsonify(dict(access_keys=result))


@blueprint.route('/<backend>/', methods=['POST'])
@login_required({'credentials'})
def create_credential(backend):
    '''
    Generate a credential (keypair/token) for user

    :query expire: expiration time in seconds, default to 3600

    **Example:**
    .. code-block:: http

           POST /hmac/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json

    .. code-block:: JavaScript
        cdis:
        {
            "token": "token_value"
        }
        google:
        {
            "name": string,
            "privateKeyType": enum(ServiceAccountPrivateKeyType),
            "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
            "privateKeyData": string,
            "publicKeyData": string,
            "validAfterTime": string,
            "validBeforeTime": string,
        }

        "privateKeyData" contains base64-encoded string that represents
        a JSON key in Google Credentials File format:
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
        other:
        {
            "access_key": "8DGW9LyC0D4nByoWo6pp",
            "secret_key": "1lnkGScEH8Vr4EC6QnoqLK1PqRWPNqIBJkH6Vpgx"
        }
    '''
    client_id = getattr(g, "client_id", None)
    if backend == 'cdis':
        result = create_refresh_token(
            g.user, capp.keypairs[0],
            request.args.get('expire', 2592000),
            request.args.get('scope', []),
            client_id
        )
        return jsonify(dict(token=result))
    elif backend == 'google':
        with GoogleCloudManager() as g_cloud:
            key = _get_google_access_key(g_cloud)
        return jsonify(key)
    else:
        return jsonify(capp.storage_manager.create_keypair(backend, g.user))


@blueprint.route('/<backend>/', methods=['PUT'])
@login_required({'credentials'})
def create_access_token_api(backend):
    '''
    Generate a credential (keypair/token) for user

    :query expire: expiration time in seconds, default to 3600

    **Example:**
    .. code-block:: http

           POST /hmac/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json

    .. code-block:: JavaScript
        cdis:
        {
            "access_token" "token_value"
        }
        google:
        {
            "name": string,
            "privateKeyType": enum(ServiceAccountPrivateKeyType),
            "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
            "privateKeyData": string,
            "publicKeyData": string,
            "validAfterTime": string,
            "validBeforeTime": string,
        }

        "privateKeyData" contains base64-encoded string that represents
        a JSON key in Google Credentials File format:
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
        other:
        {
            "access_key": "8DGW9LyC0D4nByoWo6pp",
            "secret_key": "1lnkGScEH8Vr4EC6QnoqLK1PqRWPNqIBJkH6Vpgx"
        }
    '''
    client_id = getattr(g, "client_id", None)
    if backend == 'cdis':
        result = create_access_token(
            g.user, capp.keypairs[0],
            request.form['refresh_token'],
            request.args.get('expire', 2592000),
            request.args.get('scope', []),
            client_id
        )
        return jsonify(dict(access_token=result))
    elif backend == 'google':
        with GoogleCloudManager() as g_cloud:
            key = _get_google_access_key(g_cloud)
        return jsonify(key)
    else:
        return jsonify(capp.storage_manager.create_keypair(backend, g.user))


@blueprint.route('/<backend>/<access_key>/', methods=['DELETE'])
@login_required({'credentials'})
def delete_credential(backend, access_key):
    '''
    .. http:get: /hmac/(string: access_key)
    Revoke a credential for user

    :param access_key: existing access key belongs to this user

    :statuscode 201 Success
    :statuscode 403 Forbidden to delete access key
    :statuscode 404 Access key doesn't exist

    '''
    if backend == 'cdis':
        status = revoke_refresh_token(access_key)
    elif backend == 'google':
        with GoogleCloudManager() as g_cloud:
            service_account = _get_google_service_account_for_client(g_cloud)

            if service_account:
                keys_for_account = (
                    g_cloud.get_service_account_keys_info(service_account.google_unique_id)
                )

                # Only delete the requested key if is owned by current client's SA
                if access_key in [key["name"].split("/")[-1] for key in keys_for_account]:
                    g_cloud.delete_service_account_key(service_account.google_unique_id,
                                                       access_key)
                    status = '', 200
                else:
                    abort(404, "Could not delete key " + access_key + ". Not found for current user.")
            else:
                abort(404, "Could not find service account for current user.")
    else:
        capp.storage_manager.delete_keypair(backend, g.user, access_key)
        status = '', 200

    return status


def _get_google_access_key(g_cloud_manager):
    """
    Return an access key for current user and client.

    Args:
        g_cloud_manager (cirrus.GoogleCloudManager): instance of
        cloud manager to use

    Returns:
        .. code-block:: JavaScript

            {
                "name": string,
                "privateKeyType": enum(ServiceAccountPrivateKeyType),
                "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
                "privateKeyData": string,
                "publicKeyData": string,
                "validAfterTime": string,
                "validBeforeTime": string,
            }

            "privateKeyData" contains base64-encoded string that represents
            a JSON key in Google Credentials File format:
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
    service_account = _get_google_service_account_for_client(g_cloud_manager)

    if not service_account:
        service_account = _create_google_service_account_for_client(g_cloud_manager)

    key = g_cloud_manager.get_access_key(service_account.google_unique_id)
    return key


def _get_google_service_account_for_client(g_cloud_manager):
    """
    Return the service account (from Fence db) for current client.

    Get the service account that is associated with the current client
    for this user. There will be a single service account per client.

    NOTE: The user themselves will also have a single service account
          which will be used when "client_id" is their user.id

    Args:
        g_cloud_manager (cirrus.GoogleCloudManager): instance of
        cloud manager to use

    Returns:
        fence.data_model.models.GoogleServiceAccount: Client's service account
    """
    client_id = getattr(g, "client_id", None)
    service_account = (
        current_session
        .query(GoogleServiceAccount)
        .filter_by(client_id=client_id,
                   user_id=g.user.id)
        .first()
    )

    return service_account


def _create_google_service_account_for_client(g_cloud_manager):
    """
    Create a Google Service account for the current client and user.

    Args:
        g_cloud_manager (cirrus.GoogleCloudManager): instance of
        cloud manager to use

    Returns:
        fence.data_model.models.GoogleServiceAccount: New service account
    """
    # create service account, add to db
    proxy_group = (
        current_session
        .query(GoogleProxyGroup)
        .filter_by(user_id=g.user.id)
        .first()
    )

    if proxy_group:
        client_id = getattr(g, "client_id", None)
        new_service_account = (
            g_cloud_manager.create_service_account_for_proxy_group(proxy_group.id,
                                                                   account_id=client_id)
        )

        service_account = GoogleServiceAccount(
            google_unique_id=new_service_account["uniqueId"],
            client_id=client_id,
            user_id=g.user.id,
            email=new_service_account["email"]
        )
        current_session.add(service_account)
        current_session.commit()
    else:
        # TODO Should we create a group here if one doesn't exist for some reason?
        # These groups *should* get created during dpbap sync
        abort(404, "Could not find Google proxy group for current user.")

    return service_account
