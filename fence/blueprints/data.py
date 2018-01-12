import flask
import jwt
import json
import requests
from ..auth import login_required
from ..errors import UnavailableError, NotFound, Unauthorized
from flask import current_app as capp
from flask import jsonify
from urlparse import urlparse
from ..utils import hash_secret


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
@hash_secret
def download_file(file_id):
    '''
    TODO: switch to be allowable by normal users and check authorization
    info against gdcapi
    '''
    return get_file('get_object', file_id)


@blueprint.route('/upload/<file_id>', methods=['GET'])
@hash_secret
def upload_file(file_id):
    '''
    TODO: switch to be allowable by normal users and check authorization
    info against gdcapi
    '''
    return get_file('put_object', file_id)


def get_file(action, file_id):
    doc = json.loads(get_index_document(file_id))
    if not check_authorization(doc):
        raise Unauthorized("You don't have access permission on this file")
    urls = doc['urls']
    if len(urls) != 0:
        # TODO: better way to decide which url to return
        for url in urls:
            location = urlparse(url)
            if location.scheme == 'http' or location.scheme == 'https':
                return url
            elif location.scheme == 's3':
                path = location.path.split('/', 2)
                url = capp.boto.presigned_url(path[1], path[2], action)
                return jsonify(dict(url=url))
    raise NotFound("Can't find a downloadable location for the data")


def get_user_auth_ids():
    token = jwt.decode(flask.request.headers['Authorization'].split(' ')[-1], verify=False)
    return token['context']['user']['projects']


def filter_auth_ids(list_auth_ids):
    authorized_dbgaps = []
    for key, values in list_auth_ids.items():
        if ('read-storage' in values):
            authorized_dbgaps.append(key)
    return authorized_dbgaps


def check_authorization(doc):
    metadata = doc['metadata']
    set_dbgaps = set(metadata['acls'].split(','))
    dbgap_accession_numbers = set(filter_auth_ids(get_user_auth_ids()))
    return len(set_dbgaps & dbgap_accession_numbers) > 0
