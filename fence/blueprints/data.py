import flask
import jwt
import json
import requests
from ..errors import UnavailableError, NotFound, Unauthorized, NotSupported
from flask import current_app as capp
from flask import jsonify, request
from urlparse import urlparse

action_dict = {
  "s3": {
    "upload": "put_object",
    "download": "get_object"
  },
  "http": {
    "upload": "put_object",
    "download": "get_object"
  }
}


def get_index_document(file_id):
    indexd_server = (
        capp.config.get('INDEXD') or
        capp.config['HOSTNAME'] + '/index')
    url = indexd_server + '/index/'
    try:
        res = requests.get(url + file_id)
    except Exception as e:
        capp.logger.exception("fail to reach indexd: {0}".format(e))
        raise UnavailableError(
            "Fail to reach id service to find data location")
    if res.status_code == 200:
        return res.json()
    elif res.status_code == 404:
        capp.logger.exception("fail to reach indexd: {0}".format(res.text))
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


SUPPORTED_PROTOCOLS = ['s3', 'http']


def check_protocol(protocol, scheme):
    if protocol is None:
        return True
    if protocol == 'http' and scheme in ['http', 'https']:
        return True
    if protocol == 's3' and scheme == 's3':
        return True
    return False


def resolve_url(location, protocol, expired_in, action):
    if protocol == 's3':
        path = location.path.split('/', 2)
        location = capp.boto.presigned_url(path[1], path[2], expired_in, action_dict[protocol][action])
    return jsonify(dict(url=location))


def return_link(action, urls):
    protocol = request.args.get('protocol', None)
    expired_in = request.args.get('expired_in', None)
    if (protocol is not None) and (protocol not in SUPPORTED_PROTOCOLS):
        raise NotSupported("The specified protocol is not supported")
    for url in urls:
        location = urlparse(url)
        if check_protocol(protocol, location.scheme):
            return resolve_url(location, protocol, expired_in, action)
    raise NotFound("Can't find a location for the data")


def get_file(action, file_id):
    doc = json.loads(get_index_document(file_id))
    token = jwt.decode(flask.request.headers['Authorization'].split(' ')[-1], verify=False)
    if not check_authorization(action, doc, token):
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


def check_authorization(action, doc, token):
    metadata = doc['metadata']
    set_dbgaps = set(metadata['acls'].split(','))
    dbgap_accession_numbers = set(filter_auth_ids(action, token['context']['user']['projects']))
    return len(set_dbgaps & dbgap_accession_numbers) > 0
