from fence.auth import login_required
import flask
from flask import current_app as capp
from flask import g, request, jsonify
from flask_sqlalchemy_session import current_session
from fence.resources.storage.cdis_jwt import create_refresh_token, list_refresh_tokens, revoke_refresh_token
import json

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
        result = list_refresh_tokens(g.user)
        return jsonify(dict(tokens=result))
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
            "token_value"
        }
        non-cdis:
        {
            "access_key": "8DGW9LyC0D4nByoWo6pp",
            "secret_key": "1lnkGScEH8Vr4EC6QnoqLK1PqRWPNqIBJkH6Vpgx"
        }
    '''
    if backend == 'cdis':
        result = create_refresh_token(
            g.user, capp.keypairs[0],
            request.args.get('expire', 2592000))
        return jsonify(dict(token=result))
    else:
        return jsonify(capp.storage_manager.create_keypair(backend, g.user))


@blueprint.route('/<backend>/<access_key>', methods=['DELETE'])
@login_required({'credentials'})
def delete_credential(backend, access_key):
    '''
    .. http:get: /hmac/(string: access_key)
    Revoke a credential (keypair/token) for user

    :param access_key: existing access key belongs to this user

    :statuscode 201 Success
    :statuscode 404 access key doesn't exist

    '''
    if backend == 'cdis':
        revoke_refresh_token(access_key)
    else:
        capp.storage_manager.delete_keypair(backend, g.user, access_key)
    return '', 201
