import json

from cirrus import GoogleCloudManager
from cirrus.google_cloud import get_valid_service_account_id_for_client

from flask_sqlalchemy_session import current_session
import flask

from fence.auth import require_auth_header
from fence.auth import current_token
from fence.errors import NotSupported, UserError
from fence.jwt.blacklist import blacklist_token
from fence.jwt.token import USER_ALLOWED_SCOPES
from fence.models import (
    GoogleServiceAccount,
    UserRefreshToken
)
from userdatamodel.models import User
from userdatamodel.models import GoogleProxyGroup

from fence.resources.storage.cdis_jwt import (
    create_user_access_token,
    create_api_key,
)
from fence.resources.storage import get_endpoints_descriptions


blueprint = flask.Blueprint('credentials', __name__)

ALL_RESOURCES = {
    '/cdis': 'access to CDIS APIs',
    '/ceph': 'access to Ceph storage',
    '/cleversafe': 'access to cleversafe storage',
    '/aws-s3': 'access to AWS S3 storage',
    '/google': 'access to Google storage'
}


@blueprint.route('/', methods=['GET'])
@require_auth_header({'credentials'})
def list_sources():
    """
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
    """
    services = flask.current_app.config.get('STORAGES', [])
    return flask.jsonify(get_endpoints_descriptions(services, current_session))


@blueprint.route('/<provider>/', methods=['GET'])
@require_auth_header({'credentials'})
def list_keypairs(provider):
    """
    List access keys for user

    **Example:**
    .. code-block:: http

           POST /credentials/apis/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json


    google:
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

    other:

    .. code-block:: JavaScript
        cdis
        {
            "jtis":
            [
               {"jti": "e9d58890-99b0-44f0-88bd-3ebc370b1329", "exp": 12345678},
               {"jti": "e9d58890-99b0-44f0-88bd-3ebc370b132a", "exp": 17245678}
            ]
        }
        non-cdis
        {
            "access_keys":
            [
                {
                    "access_key": "8DGW9LyC0D4nByoWo6pp",
                }
            ]
        }

    """
    client_id = current_token.get("azp") or None
    user_id = current_token["sub"]

    if provider == 'cdis':
        with flask.current_app.db.session as session:
            tokens = (
                session
                .query(UserRefreshToken)
                .filter_by(userid=user_id)
                .order_by(UserRefreshToken.expires.desc())
                .all()
            )
            result = {
                'jtis':
                    [{'jti': item.jti, 'exp': item.expires} for item in tokens]}
    elif provider == 'google':
        with GoogleCloudManager() as g_cloud_manager:
            service_account = _get_google_service_account_for_client(
                g_cloud_manager, client_id, user_id)

            if service_account:
                keys = g_cloud_manager.get_service_account_keys_info(
                    service_account.google_unique_id)
                result = {'access_keys': keys}
            else:
                result = {'access_keys': []}
    else:
        # TODO hopefully we can remove this db call eventually, but
        # StorageManager class requires some updates
        with flask.current_app.db.session as session:
            user = (
                session
                .query(User)
                .filter_by(id=user_id)
                .first()
            )

        result = (
            flask.current_app
            .storage_manager
            .list_keypairs(provider, user)
        )
        keys = {
            'access_keys':
                [{'access_key': item['access_key']} for item in result]}
        result = keys
    return flask.jsonify(result)


@blueprint.route('/<provider>/', methods=['POST'])
@require_auth_header({'credentials'})
def create_keypairs(provider):
    """
    Generate a keypair for user

    :query expires_in: expiration time in seconds, default and max is 30 days

    **Example:**
    .. code-block:: http

           POST /credentials/cdis/?expires_in=3600 HTTP/1.1
           Content-Type: application/json
           Accept: application/json

    cdis:

    .. code-block:: JavaScript

        {
            "key_id": result,
            "api_key": result
        }

    google:
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

    other:

    .. code-block:: JavaScript

        {
            "access_key": "8DGW9LyC0D4nByoWo6pp",
            "secret_key": "1lnkGScEH8Vr4EC6QnoqLK1PqRWPNqIBJkH6Vpgx"
        }
    """
    client_id = current_token.get("azp") or None
    user_id = current_token["sub"]

    if provider == 'cdis':
        # fence identifies access_token endpoint, openid is the default
        # scope for service endpoints
        default_scope = ['fence', 'openid']
        content_type = flask.request.headers.get('Content-Type')
        if content_type == 'application/x-www-form-urlencoded':
            scope = flask.request.form.getlist('scope')
        else:
            try:
                scope = (
                    json.loads(flask.request.data)
                    .get('scope')
                ) or []
            except ValueError:
                scope = []
        if not isinstance(scope, list):
            scope = scope.split(',')
        scope.extend(default_scope)
        for s in scope:
            if s not in USER_ALLOWED_SCOPES:
                raise NotSupported('Scope {} is not supported'.format(s))
        expires_in = min(
            int(flask.request.args.get('expires_in', 2592000)),
            2592000
        )
        api_key, claims = create_api_key(
            user_id, flask.current_app.keypairs[0], expires_in, scope,
            client_id
        )
        return flask.jsonify(dict(key_id=claims['jti'], api_key=api_key))
    elif provider == 'google':
        with GoogleCloudManager() as g_cloud:
            client_id = current_token.get("azp") or None
            key = _get_google_access_key_for_client(g_cloud, client_id, user_id)
        return flask.jsonify(key)
    else:
        # TODO hopefully we can remove this db call eventually, but
        # StorageManager class requires some updates
        with flask.current_app.db.session as session:
            user = (
                session
                .query(User)
                .filter_by(id=user_id)
                .first()
            )

        return flask.jsonify(flask.current_app.storage_manager.create_keypair(
            provider, user
        ))


@blueprint.route('/cdis/access_token', methods=['POST'])
def create_access_token_api():
    """
    Generate an access_token for user

    :query expires_in: expiration time in seconds, default to 3600, max is 3600

    **Example:**
    .. code-block:: http

           POST /hmac/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json


    .. code-block:: JavaScript

        {
            "token" "token_value"
        }
    """
    if flask.request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
        api_key = flask.request.form.get('api_key')
    else:
        try:
            api_key = json.loads(flask.request.data).get('api_key')
        except ValueError:
            api_key = None
    if not api_key:
        raise UserError('Please provide an api_key in payload')
    expires_in = min(int(flask.request.args.get('expires_in', 3600)), 3600)
    result = create_user_access_token(
        flask.current_app.keypairs[0], api_key, expires_in
    )
    return flask.jsonify(dict(access_token=result))


@blueprint.route('/<provider>/<access_key>', methods=['DELETE'])
@require_auth_header({'credentials'})
def delete_keypair(provider, access_key):
    """
    .. http:get: /<provider>/(string: access_key)
    Delete a keypair for user

    :param access_key: existing access key that belongs to this user

    For Google:
        The access_key can be constructed from
        data in the response from creating the key.

        access_key should be a string:
        `projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}/keys/{KEY}`
        which can be constructed with the information from POST/PUT `credentials/google`
        Use `project_id` for {PROJECT_ID},
            `client_email` for {ACCOUNT},
            `private_key_id` for {KEY}

    :statuscode 201 Success
    :statuscode 403 Forbidden to delete access key
    :statuscode 404 Access key doesn't exist

    """
    user_id = current_token["sub"]

    if provider == 'cdis':
        jti = access_key
        with flask.current_app.db.session as session:
            api_key = (
                session
                .query(UserRefreshToken)
                .filter_by(jti=jti, userid=user_id)
                .first()
            )
        if not api_key:
            flask.abort(400, 'token not found with JTI {}'.format(jti))
        blacklist_token(jti, api_key.expires)
    elif provider == 'google':
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
    else:
        # TODO hopefully we can remove this db call eventually, but
        # StorageManager class requires some updates
        with flask.current_app.db.session as session:
            user = (
                session
                .query(User)
                .filter_by(id=user_id)
                .first()
            )

        flask.current_app.storage_manager.delete_keypair(
            provider, user, access_key)

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
