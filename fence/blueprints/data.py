import re

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
    get_or_create_primary_service_account_key,
    create_primary_service_account_key
)
from fence.errors import UnavailableError
from fence.errors import NotFound
from fence.errors import Unauthorized
from fence.errors import NotSupported
from fence.errors import InternalError

ACTION_DICT = {
    's3': {
        'upload': 'PUT',
        'download': 'GET'
    },
    'gs': {
        'upload': 'PUT',
        'download': 'GET'
    },
}

SUPPORTED_PROTOCOLS = ['s3', 'http', 'ftp', 'https', 'gs']
SUPPORTED_ACTIONS = ['upload', 'download']


blueprint = flask.Blueprint('data', __name__)


@blueprint.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    '''
    Get a presigned url to download a file given by file_id.
    '''
    result = get_signed_url_for_file('download', file_id)
    if not 'redirect' in flask.request.args or not 'url' in result:
        return flask.jsonify(result)
    else:
        return flask.redirect(result['url'])


@blueprint.route('/upload/<file_id>', methods=['GET'])
def upload_file(file_id):
    '''
    Get a presigned url to upload a file given by file_id.
    '''
    result = get_signed_url_for_file('upload', file_id)
    return flask.jsonify(result)


def get_signed_url_for_file(action, file_id):
    requested_protocol = flask.request.args.get('protocol', None)
    max_ttl = flask.current_app.config.get('MAX_PRESIGNED_URL_TTL', 3600)
    expires_in = min(
        int(flask.request.args.get('expires_in', max_ttl)), max_ttl)

    indexed_file = IndexedFile(file_id)
    signed_url = indexed_file.get_signed_url(
        requested_protocol, action, expires_in)

    return {'url': signed_url}


class IndexedFile(object):
    """
    A file from the index service that will contain information about
    access and where the physical file lives (could be multiple urls).
    """

    def __init__(self, file_id):
        self.file_id = file_id
        self.index_document = self._get_index_document()
        self.metadata = self.index_document.get('metadata', {})
        self.set_acls = self._get_acls()
        self.indexed_file_locations = (
            self._get_indexed_file_locations(
                self.index_document.get('urls', []))
        )
        self.public = check_public(self.set_acls)

    def get_signed_url(self, protocol, action, expires_in):
        if not self.public and not self.check_authorization(action):
            raise Unauthorized("You don't have access permission on this file")

        if action is not None and action not in SUPPORTED_ACTIONS:
            raise NotSupported(
                "action {} is not supported".format(action))

        return self._get_signed_url(protocol, action, expires_in)

    def _get_signed_url(self, protocol, action, expires_in):
        signed_url = None

        if protocol:
            for file_location in self.indexed_file_locations:
                # allow file location to be https, even if they specific http
                if ((file_location.protocol == protocol)
                        or (protocol == 'http' and file_location.protocol == 'https')):
                    signed_url = file_location.get_signed_url(
                        action, expires_in, public_data=self.public)

        # no protocol specified, return first location as signed url
        elif len(self.indexed_file_locations) > 0:
            signed_url = self.indexed_file_locations[0].get_signed_url(
                action, expires_in, public_data=self.public)
        else:
            # will get caught below when signed_url is still None
            pass

        if not signed_url:
            raise NotFound(
                'File {} does not have a location with specified '
                'protocol {}.'.format(self.file_id, protocol))

        return signed_url

    def _get_index_document(self):
        indexd_server = (
                flask.current_app.config.get('INDEXD') or
                flask.current_app.config['BASE_URL'] + '/index')
        url = indexd_server + '/index/'
        try:
            res = requests.get(url + self.file_id)
        except Exception as e:
            flask.current_app.logger.error(
                "failed to reach indexd at {0}: {1}"
                .format(url + self.file_id, e))
            raise UnavailableError(
                "Fail to reach id service to find data location")
        if res.status_code == 200:
            try:
                json_response = res.json()
                if 'urls' not in json_response:
                    flask.current_app.logger.error(
                        'URLs are not included in response from '
                        'indexd: {}'.format(url + self.file_id)
                    )
                    raise InternalError('URLs and metadata not found')
                return res.json()
            except Exception as e:
                flask.current_app.logger.error(
                    'indexd response missing JSON field {}'
                    .format(url + self.file_id))
                raise InternalError('internal error from indexd: {}'.format(e))
        elif res.status_code == 404:
            flask.current_app.logger.error(
                'Not Found. indexd could not find {}'
                '\nIndexd\'s response: {}'
                .format(url + self.file_id, res.text))
            raise NotFound("Can't find a location for the data")
        else:
            raise UnavailableError(res.text)

    def _get_acls(self):
        if 'acl' in self.index_document:
            set_acls = set(self.index_document['acl'])
        elif 'acls' in self.metadata:
            set_acls = set(self.metadata['acls'].split(','))
        else:
            raise Unauthorized("This file is not accessible")

        return set_acls

    @staticmethod
    def _get_indexed_file_locations(urls):
        indexed_file_locations = []
        for url in urls:
            new_location = IndexedFileLocationFactory.create(url)
            indexed_file_locations.append(new_location)
        return indexed_file_locations

    @login_required({'data'})
    def check_authorization(self, action):
        if flask.g.token is None:
            given_acls = set(filter_auth_ids(
                action, flask.g.user.project_access))
        else:
            given_acls = set(filter_auth_ids(
                action, flask.g.token['context']['user']['projects']))
        return len(self.set_acls & given_acls) > 0


class IndexedFileLocationFactory(object):
    """
    Responsible for the creation of IndexedFileLocation objects based on
    the protocol for the given url.

    This will determine where the object lives based on the protocol in url
    (e.g. s3 or gs) and create the necessary sub-class that will handle actions
    like signing urls for that location.
    """

    @staticmethod
    def create(url):
        location = urlparse(url)
        protocol = location.scheme
        if (protocol is not None) and (protocol not in SUPPORTED_PROTOCOLS):
            raise NotSupported(
                'The specified protocol {} is not supported'
                .format(protocol))

        if protocol == 's3':
            return S3IndexedFileLocation(url)
        elif protocol == 'gs':
            return GoogleStorageIndexedFileLocation(url)
        else:
            return IndexedFileLocation(url)


class IndexedFileLocation(object):
    """
    Parent class for indexed file locations.

    This will catch all non-aws/gs cases for now. If custom functionality is
    needed for a new file location, create a new subclass.
    """

    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.protocol = self.parsed_url.scheme

    def get_signed_url(self, action, expires_in, public_data=False):
        return self.url


class S3IndexedFileLocation(IndexedFileLocation):
    """
    And indexed file that lives in an AWS S3 bucket.
    """

    def __init__(self, url):
        super(S3IndexedFileLocation, self).__init__(url)

    def get_signed_url(
            self, action, expires_in, public_data=False):
        aws_creds = get_value(
            flask.current_app.config, 'AWS_CREDENTIALS',
            InternalError('credentials not configured'))

        s3_buckets = get_value(
            flask.current_app.config, 'S3_BUCKETS',
            InternalError('buckets not configured'))

        http_url = (
            'https://{}.s3.amazonaws.com/{}'
            .format(self.parsed_url.netloc, self.parsed_url.path.strip('/'))
        )

        if len(aws_creds) > 0:
            credential_key = None
            for pattern in s3_buckets:
                if re.match(pattern, self.parsed_url.netloc):
                    credential_key = s3_buckets[pattern]
                    break
            if credential_key is None:
                raise Unauthorized('permission denied for bucket')

            # public bucket
            if credential_key == '*':
                return http_url
            if credential_key not in aws_creds:
                raise Unauthorized('permission denied for bucket')

        config = get_value(
            aws_creds, credential_key,
            InternalError('aws credential of that bucket is not found'))

        region = flask.current_app.boto.get_bucket_region(
            self.parsed_url.netloc, config)

        if 'aws_access_key_id' not in config:
            raise Unauthorized('credential is not configured correctly')
        else:
            aws_access_key_id = get_value(
                config, 'aws_access_key_id',
                InternalError('aws configuration not found'))
            aws_secret_key = get_value(
                config, 'aws_secret_access_key',
                InternalError('aws configuration not found'))

        user_info = {}
        if not public_data:
            user_info = S3IndexedFileLocation.get_user_info()

        url = generate_aws_presigned_url(
            http_url, ACTION_DICT['s3'][action], aws_access_key_id,
            aws_secret_key, 's3', region, expires_in, user_info)

        return url

    @staticmethod
    def get_user_info():
        user_info = {}
        set_current_token(validate_request(aud={'user'}))
        user_id = current_token['sub']
        username = current_token['context']['user']['name']
        if user_id is not None:
            user_info = {'user_id': str(user_id), 'username': username}
        return user_info


class GoogleStorageIndexedFileLocation(IndexedFileLocation):
    """
    And indexed file that lives in a Google Storage bucket.
    """

    def __init__(self, url):
        super(GoogleStorageIndexedFileLocation, self).__init__(url)

    def get_signed_url(self, action, expires_in, public_data=False):
        resource_path = (
            self.parsed_url.netloc.strip('/') + '/'
            + self.parsed_url.path.strip('/')
        )

        # if the file is public, just return the public url to access it, no
        # signing required
        if public_data:
            url = 'https://storage.googleapis.com/' + resource_path
        else:
            expiration_time = int(time.time()) + int(expires_in)
            url = self._generate_google_storage_signed_url(
                ACTION_DICT['gs'][action], resource_path, expiration_time)

        return url

    def _generate_google_storage_signed_url(
            self, http_verb, resource_path, expiration_time):
        set_current_token(validate_request(aud={'user'}))
        user_id = current_token['sub']
        proxy_group_id = (
            current_token.get('context', {})
            .get('user', {})
            .get('google', {})
            .get('proxy_group')
        )
        username = (
            current_token.get('context', {})
            .get('user', {})
            .get('name')
        )

        private_key, key_db_entry = (
            get_or_create_primary_service_account_key(
                user_id=user_id,
                username=username,
                proxy_group_id=proxy_group_id)
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
            private_key = create_primary_service_account_key(
                user_id=user_id,
                username=username,
                proxy_group_id=proxy_group_id
            )

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
