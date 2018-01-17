from ..auth import login_required
import flask
from flask import current_app as capp
from flask import g, request, jsonify
from flask_sqlalchemy_session import current_session

from ..resources.storage import get_endpoints_descriptions
from fence.resources.storage.cdis_jwt import create_refresh_token,\
    revoke_refresh_token, create_access_token

blueprint = flask.Blueprint('credentials', __name__)

ALL_RESOURCES = {
    "/cdis": "access to CDIS APIs",
    "/ceph": "access to Ceph storage",
    "/cleversafe": "access to cleversafe storage",
    "/aws-s3": "access to AWS S3 storage"
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
        }
    '''
    services = capp.config.get('STORAGES', [])
    return jsonify(get_endpoints_descriptions(services, current_session))


@blueprint.route('/<provider>/', methods=['GET'])
@login_required({'credentials'})
def list_keypairs(provider):
    '''
    List access keys for user

    **Example:**
    .. code-block:: http

           POST /credentials/apis/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json

    .. code-block:: JavaScript

        {
            "access_keys":
            [
                {
                    "access_key": "8DGW9LyC0D4nByoWo6pp",
                }
            ]
        }

    '''
    if provider != 'cdis':
        result = capp.storage_manager.list_keypairs(provider, g.user)
        keys = {
            'access_keys':
            [{'access_key': item['access_key']} for item in result]}
        return jsonify(keys)
    return jsonify({'error': 'not supported'})


@blueprint.route('/<provider>/', methods=['POST'])
@login_required({'credentials'})
def create_keypairs(provider):
    '''
    Generate a keypair for user

    :query expire: expiration time in seconds, default to 3600

    **Example:**
    .. code-block:: http

           POST /hmac/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json

    .. code-block:: JavaScript
        cdis:
        {
            "token" "token_value"
        }
        non-cdis:
        {
            "access_key": "8DGW9LyC0D4nByoWo6pp",
            "secret_key": "1lnkGScEH8Vr4EC6QnoqLK1PqRWPNqIBJkH6Vpgx"
        }
    '''
    if provider == 'cdis':
        scopes = request.args.get('scopes', [])
        if not isinstance(scopes, list):
            scopes = scopes.split(',')
        result = create_refresh_token(
            g.user, capp.keypairs[0],
            request.args.get('expire', 2592000),
            scopes
        )
        return jsonify(dict(token=result))
    else:
        return jsonify(capp.storage_manager.create_keypair(provider, g.user))


@blueprint.route('/<provider>/', methods=['PUT'])
@login_required({'credentials'})
def create_access_token_api(provider):
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
        non-cdis:
        {
            "access_key": "8DGW9LyC0D4nByoWo6pp",
            "secret_key": "1lnkGScEH8Vr4EC6QnoqLK1PqRWPNqIBJkH6Vpgx"
        }
    '''
    if provider == 'cdis':
        scopes = request.args.get('scopes', [])
        if not isinstance(scopes, list):
            scopes = scopes.split(',')
        result = create_access_token(
            g.user, capp.keypairs[0],
            request.form['refresh_token'],
            request.args.get('expire', 2592000),
            scopes
        )
        return jsonify(dict(access_token=result))
    else:
        return jsonify(capp.storage_manager.create_keypair(provider, g.user))


@blueprint.route('/<provider>/<access_key>', methods=['DELETE'])
@login_required({'credentials'})
def delete_keypair(provider, access_key):
    '''
    .. http:get: /<provider>/(string: access_key)
    Delete a keypair for user

    :param access_key: existing access key belongs to this user

    :statuscode 201 Success
    :statuscode 404 access key doesn't exist

    '''
    if provider == 'cdis':
        return revoke_refresh_token(access_key)
    else:
        capp.storage_manager.delete_keypair(provider, g.user, access_key)
    return '', 201
