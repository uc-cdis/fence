from auth import login_required
import flask
from flask import current_app as capp
from flask import g, request, jsonify
from flask_sqlalchemy_session import current_session
import datetime
from .utils import json_res
from .resources.storage.cdis import create_keypair, delete_keypair


blueprint = flask.Blueprint('hmac', __name__)


@blueprint.route('/', methods=['GET'])
@login_required({'hmac'})
def list_hmac_keypairs():
    '''
    List all keypairs with UTC expiration time for user
    **Example:**
    .. code-block:: http
           GET /hmac/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json
    .. code-block:: JavaScript
        [
            {
                "access_key": "8DGW9LyC0D4nByoWo6pp"
                "expire": "2016-11-08 21:39:01.520493"
            }
        ]
    '''
    result = []

    for keypair in g.user.hmac_keypairs:
        if not keypair.check_and_archive(current_session):
            result.append({
                'access_key': keypair.access_key,
                'expire': str(keypair.timestamp
                              + datetime.timedelta(seconds=keypair.expire))})

    return json_res(result)


@blueprint.route('/', methods=['POST'])
@login_required({'hmac'})
def generate_hmac_keypairs():
    '''
    Generate a hmac keypair for user
    :query expire: expiration time in seconds, default to 3600
    **Example:**
    .. code-block:: http
           POST /hmac/ HTTP/1.1
           Content-Type: application/json
           Accept: application/json
    .. code-block:: JavaScript
        [
            {
                "access_key": "8DGW9LyC0D4nByoWo6pp",
                "secret_key": "1lnkGScEH8Vr4EC6QnoqLK1PqRWPNqIBJkH6Vpgx"
            }
        ]
    '''
    result = create_keypair(
        g.user, current_session,
        capp.config['HMAC_ENCRYPTION_KEY'], request.args.get('expire', 86400))

    return jsonify(result)


@blueprint.route('/<access_key>', methods=['DELETE'])
@login_required({'hmac'})
def delete_hmac_keypair(access_key):
    '''
    .. http:get: /hmac/(string: access_key)
    Delete a hmac keypair for user
    :param access_key: existing access key belongs to this user
    :statuscode 201 Success
    :statuscode 404 access key doesn't exist
    '''
    delete_keypair(g.user, current_session, access_key)
    return '', 201
