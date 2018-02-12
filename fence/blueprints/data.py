from urlparse import urlparse

import flask
from flask import current_app
import requests

from fence.auth import login_required
from fence.errors import (
    UnavailableError,
    NotFound,
    Unauthorized,
    NotSupported,
    InternalError,
)

ACTION_DICT = {
    "s3": {
        "upload": "put_object",
        "download": "get_object"
    },
    "http": {
        "upload": "put_object",
        "download": "get_object"
    }
}

SUPPORTED_PROTOCOLS = ['s3', 'http']


def get_index_document(file_id):
    indexd_server = (
            current_app.config.get('INDEXD') or
            current_app.config['BASE_URL'] + '/index')
    url = indexd_server + '/index/'
    try:
        res = requests.get(url + file_id)
    except Exception as e:
        current_app.logger.error("failed to reach indexd at {0}: {1}".format(url + file_id, e))
        raise UnavailableError(
            "Fail to reach id service to find data location")
    if res.status_code == 200:
        try:
            json_response = res.json()
            if 'urls' not in json_response or 'metadata' not in json_response:
                current_app.logger.error(
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
@login_required({'data'})
def download_file(file_id):
    '''
    Get a presigned url to download a file given by file_id.
    '''
    return get_file('download', file_id)


@blueprint.route('/upload/<file_id>', methods=['GET'])
@login_required({'data'})
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


def resolve_url(url, location, expires, action):
    protocol = location.scheme
    if protocol == 's3':
        aws_creds = current_app.config['AWS_CREDENTIALS']
        if 'AWS_CREDENTIALS' in current_app.config and len(aws_creds) > 0:
            buckets = flask.current_app.config['S3_BUCKETS']
            if location.netloc not in buckets.keys():
                raise Unauthorized('permission denied for bucket')
            if buckets[location.netloc] not in aws_creds:
                raise Unauthorized('permission denied for bucket')
        credential_key = buckets[location.netloc]
        url = current_app.boto.presigned_url(
            location.netloc,
            location.path.strip('/'),
            expires,
            aws_creds[credential_key],
            ACTION_DICT[protocol][action],
        )
    elif protocol not in ['http', 'https']:
        raise NotSupported(
            'protocol {} in URL {} is not supported'.format(protocol, url)
        )
    return flask.jsonify(dict(url=url))


def return_link(action, urls):
    protocol = flask.request.args.get('protocol', None)
    expires = min(int(flask.request.args.get('expires_in', 3600)), 3600)
    if (protocol is not None) and (protocol not in SUPPORTED_PROTOCOLS):
        raise NotSupported("The specified protocol is not supported")
    if len(urls) == 0:
        raise NotFound("Can't find any location for the data")
    for url in urls:
        location = urlparse(url)
        if check_protocol(protocol, location.scheme):
            return resolve_url(url, location, expires, action)
    raise NotFound(
        "Can't find a location for the data with given request arguments."
    )


def get_file(action, file_id):
    doc = get_index_document(file_id)
    if not check_authorization(action, doc):
        raise Unauthorized("You don't have access permission on this file")
    return return_link(action, doc['urls'])


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


def check_authorization(action, doc):
    metadata = doc['metadata']
    if 'acls' not in metadata:
        raise Unauthorized("You don't have access permission on this file")
    set_acls = set(metadata['acls'].split(','))
    if flask.g.token is None:
        given_acls = set(filter_auth_ids(action, flask.g.user.project_access))
    else:
        given_acls = set(filter_auth_ids(action, flask.g.token['context']['user']['projects']))
    return len(set_acls & given_acls) > 0
