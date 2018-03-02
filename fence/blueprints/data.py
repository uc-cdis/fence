import flask
import requests
from urlparse import urlparse
from fence.auth import login_required
from cdispyutils.hmac4 import generate_aws_presigned_url
from cdispyutils.config import get_value
from ..errors import UnavailableError, NotFound, Unauthorized, NotSupported, InternalError

ACTION_DICT = {
    "s3": {
        "upload": "PUT",
        "download": "GET"
    },
    "http": {
        "upload": "put_object",
        "download": "get_object"
    }
}

SUPPORTED_PROTOCOLS = ['s3', 'http']


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


blueprint = flask.Blueprint('data', __name__)


@blueprint.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    '''
    Get a presigned url to download a file given by file_id.
    '''
    return get_file('download', file_id)


@blueprint.route('/upload/<file_id>', methods=['GET'])
def upload_file(file_id):
    '''
    Get a presigned url to upload a file given by file_id.
    '''
    return get_file('upload', file_id)


def check_protocol(protocol, scheme):
    if protocol is None:
        return True
    if protocol == 'http' and scheme in ['http', 'https']:
        return True
    if protocol == 's3' and scheme == 's3':
        return True
    return False


def resolve_url(url, location, expires, action, user_id, username):
    protocol = location.scheme
    if protocol == 's3':
        aws_creds = get_value(flask.current_app.config, 'AWS_CREDENTIALS',
                              InternalError('credentials not configured'))
        s3_buckets = get_value(flask.current_app.config, 'S3_BUCKETS',
                               InternalError('buckets not configured'))
        if len(aws_creds) > 0:
            if location.netloc not in s3_buckets.keys():
                raise Unauthorized('permission denied for bucket')
            if location.netloc in s3_buckets.keys() and \
                    s3_buckets[location.netloc] not in aws_creds:
                raise Unauthorized('permission denied for bucket')
        credential_key = s3_buckets[location.netloc]
        config = get_value(aws_creds, credential_key,
                           InternalError('aws credential of that bucket is not found'))
        region = flask.current_app.boto.get_bucket_region(location.netloc, config)
        http_url = 'https://{}.s3.amazonaws.com/{}'.format(location.netloc, location.path.strip('/'))
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
        url = generate_aws_presigned_url(http_url, ACTION_DICT[protocol][action],
                                         aws_access_key_id, aws_secret_key, 's3',
                                         region, expires, user_info)
    elif protocol not in ['http', 'https']:
        raise NotSupported(
            "protocol {} in url {} is not supported".format(protocol, url))
    return flask.jsonify(dict(url=url))


def return_link(action, urls, user_id=None, username=None):
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
            return resolve_url(url, location, expires, action, user_id, username)
    raise NotFound(
        "Can't find a location for the data with given request arguments."
    )


def get_file(action, file_id):
    doc = get_index_document(file_id)
    metadata = doc['metadata']
    if 'acls' not in metadata:
        raise Unauthorized("This file is not accessible")
    set_acls = set(metadata['acls'].split(','))
    if check_public(set_acls):
        return return_link(action, doc['urls'])
    if not check_authorization(action, set_acls):
        raise Unauthorized("You don't have access permission on this file")
    return return_link(action, doc['urls'], flask.g.user.id, flask.g.user.username)


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
