import flask
import requests
import time
from urlparse import urlparse

import cirrus
from fence.auth import login_required
from fence.auth import set_current_token
from fence.auth import validate_request
from fence.auth import current_token
from cdispyutils.hmac4 import generate_aws_presigned_url
from cdispyutils.config import get_value

from fence.resources.google.utils import (
    get_or_create_users_primary_google_service_account_key,
    create_users_primary_google_service_account_key
)
from fence.errors import UnavailableError
from fence.errors import NotFound
from fence.errors import Unauthorized
from fence.errors import NotSupported
from fence.errors import InternalError

ACTION_DICT = {
    "s3": {
        "upload": "PUT",
        "download": "GET"
    },
    "http": {
        "upload": "put_object",
        "download": "get_object"
    },
    "gs": {
        "upload": "PUT",
        "download": "GET"
    },
}

SUPPORTED_PROTOCOLS = ['s3', 'http', 'ftp', 'https', 'gs']


blueprint = flask.Blueprint('data', __name__)



@blueprint.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    '''
    Get a presigned url to download a file given by file_id.
    '''
    result = get_file('download', file_id)
    if not 'redirect' in flask.request.args or not 'url' in result:
        return flask.jsonify(result)
    else:
        return flask.redirect(result['url'])


@blueprint.route('/upload/<file_id>', methods=['GET'])
def upload_file(file_id):
    '''
    Get a presigned url to upload a file given by file_id.
    '''
    return flask.jsonify(get_file('upload', file_id))


def get_file(action, file_id):
    doc = get_index_document(file_id)
    metadata = doc['metadata']
    if 'acls' not in metadata:
        raise Unauthorized("This file is not accessible")
    set_acls = set(metadata['acls'].split(','))
    if check_public(set_acls):
        return return_link(action, doc['urls'], public=True)
    if not check_authorization(action, set_acls):
        raise Unauthorized("You don't have access permission on this file")
    return return_link(action, doc['urls'], flask.g.user.id, flask.g.user.username)


def get_index_document(file_id):
    indexd_server = (
            flask.current_app.config.get('INDEXD') or
            flask.current_app.config['BASE_URL'] + '/index')
    url = indexd_server + '/index/'
    try:
        res = requests.get(url + file_id)
    except Exception as e:
        flask.current_app.logger.error("failed to reach indexd at {0}: {1}".format(url + file_id, e))
        raise UnavailableError(
            "Fail to reach id service to find data location")
    if res.status_code == 200:
        try:
            json_response = res.json()
            if 'urls' not in json_response or 'metadata' not in json_response:
                flask.current_app.logger.error(
                    'URLs and metadata are not included in response from indexd: {}'.format(url + file_id)
                )
                raise InternalError('URLs and metadata not found')
            return res.json()
        except Exception as e:
            flask.current_app.logger.error('indexd response missing JSON field {}'.format(url + file_id))
            raise InternalError('internal error from indexd: {}'.format(e))
    elif res.status_code == 404:
        flask.current_app.logger.error('indexd did not find find {}; {}'.format(url + file_id, res.text))
        raise NotFound("Can't find a location for the data")
    else:
        raise UnavailableError(res.text)


def return_link(action, urls, user_id=None, username=None, public=False):
    protocol = flask.request.args.get('protocol', None)
    max_ttl = flask.current_app.config.get('MAX_PRESIGNED_URL_TTL', 3600)
    expires = min(int(flask.request.args.get('expires_in', max_ttl)), max_ttl)
    if (protocol is not None) and (protocol not in SUPPORTED_PROTOCOLS):
        raise NotSupported("The specified protocol is not supported")
    if len(urls) == 0:
        raise NotFound("Can't find any location for the data")
    for url in urls:
        location = urlparse(url)
        if check_protocol(protocol, location.scheme):
            return resolve_url(
                location, expires, action, user_id, username, public)
    raise NotFound(
        "Can't find a location for the data with given request arguments."
    )


def check_protocol(protocol, scheme):
    if scheme not in SUPPORTED_PROTOCOLS:
        return False
    if protocol is None:
        return True
    if protocol == scheme:
        return True
    if protocol == 'http' and scheme in ['http', 'https']:
        return True
    return False


def resolve_url(location, expires, action, user_id, username, public=False):
    protocol = location.scheme
    if protocol == 's3':
        url = resolve_s3_url(location, expires, action, user_id, username)
    elif protocol == 'gs':
        url = resolve_gs_url(location, expires, action, public)
    elif protocol not in SUPPORTED_PROTOCOLS:
        raise NotSupported(
            "protocol {} in url {} is not supported".format(protocol, url))
    return dict(url=url)


def resolve_s3_url(location, expires, action, user_id, username):
    aws_creds = get_value(flask.current_app.config, 'AWS_CREDENTIALS',
                          InternalError('credentials not configured'))
    s3_buckets = get_value(flask.current_app.config, 'S3_BUCKETS',
                           InternalError('buckets not configured'))

    http_url = (
        'https://{}.s3.amazonaws.com/{}'
        .format(location.netloc, location.path.strip('/'))
    )
    if len(aws_creds) > 0:
        if location.netloc not in s3_buckets.keys():
            raise Unauthorized('permission denied for bucket')
        credential_key = s3_buckets[location.netloc]
        # public bucket
        if credential_key == '*':
            return http_url
        if credential_key not in aws_creds:
            raise Unauthorized('permission denied for bucket')
    config = get_value(aws_creds, credential_key,
                       InternalError('aws credential of that bucket is not found'))
    region = flask.current_app.boto.get_bucket_region(location.netloc, config)
    if 'aws_access_key_id' not in config:
        raise Unauthorized('credential is not configured correctly')
    else:
        aws_access_key_id = get_value(config, 'aws_access_key_id',
                                      InternalError('aws configuration not found'))
        aws_secret_key = get_value(config, 'aws_secret_access_key',
                                   InternalError('aws configuration not found'))
    user_info = {}
    if user_id is not None:
        user_info = {'user_id': str(user_id), 'username': username}
    url = generate_aws_presigned_url(http_url, ACTION_DICT['s3'][action],
                                     aws_access_key_id, aws_secret_key, 's3',
                                     region, expires, user_info)
    return url


def resolve_gs_url(location, expires, action, public):
    resource_path = location.path.strip('/')
    # if the file is public, just return the public url to access it, no
    # signing required
    if public:
        url = 'https://' + location.netloc.strip('/') + '/' + resource_path
    else:
        expiration_time = int(time.time()) + int(expires)
        url = generate_google_storage_signed_url(
            ACTION_DICT['gs'][action], resource_path, expiration_time)

    return url


def generate_google_storage_signed_url(
        http_verb, resource_path, expiration_time):
    set_current_token(validate_request(aud={'user'}))
    user_id = current_token["sub"]
    proxy_group_id = (
        current_token.get('context', {})
        .get('user', {})
        .get('google', {})
        .get('proxy_group')
    )

    private_key, key_db_entry = get_or_create_users_primary_google_service_account_key(
        user_id=user_id,
        proxy_group_id=proxy_group_id
    )

    # Make sure the service account key expiration is later
    # than the expiration for the signed url. If it's not, we need to
    # provision a new service account key.
    #
    # NOTE: This should occur very rarely: only when the service account key
    #       already exists and is very close to expiring.
    #
    #       If our scheduled maintainence script removes the url-signing key
    #       before the expiration of the url then the url will NOT work
    #       (even though the url itself isn't expired)
    if key_db_entry and key_db_entry.expires > expiration_time:
        private_key = create_users_primary_google_service_account_key(
            user_id=user_id,
            proxy_group_id=proxy_group_id
        )

    # expires = int(time.time())+10  # TODO REMOVE

    final_url = cirrus.google_cloud.utils.get_signed_url(
        resource_path, http_verb, expiration_time,
        extension_headers=None, content_type='', md5_value='',
        service_account_creds=private_key
    )
    return final_url


def filter_auth_ids(action, list_auth_ids):
    checked_permission = ''
    if action == 'download':
        checked_permission = 'read-storage'
    elif action == 'upload':
        checked_permission = 'write-storage'
    authorized_dbgaps = []
    for key, values in list_auth_ids.items():
        if (checked_permission in values):
            authorized_dbgaps.append(key)
    return authorized_dbgaps


def check_public(set_acls):
    if '*' in set_acls:
        return True


@login_required({'data'})
def check_authorization(action, set_acls):
    if flask.g.token is None:
        given_acls = set(filter_auth_ids(action, flask.g.user.project_access))
    else:
        given_acls = set(filter_auth_ids(action, flask.g.token['context']['user']['projects']))
    return len(set_acls & given_acls) > 0
