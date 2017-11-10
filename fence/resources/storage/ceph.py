from boto import connect_s3, connect_sts
from urllib import urlencode
from fence.errors import InternalError
from boto.s3.acl import Grant
from boto.exception import S3ResponseError
import json
from awsauth import S3Auth
import logging
from dateutil import parser
import requests
from boto.s3.connection import OrdinaryCallingFormat
from flask import current_app as capp


logger = logging.getLogger(__name__)


def handle_request(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.exception("internal error")
            raise InternalError(e)
    return wrapper


class CephClient(object):
    def __init__(self, config):
        self.config = config
        self.server = self.config['host']
        self.port = self.config['port']
        self.auth = S3Auth(
            self.config['aws_access_key_id'],
            self.config['aws_secret_access_key'],
            self.server+':'+str(self.port))
        self.conn = connect_s3(**self.config)

    def update_bucket_acl(self, bucket, read_acl):
        bucket = self.conn.get_bucket(bucket)
        policy = bucket.get_acl()
        prev_policy = policy.to_xml()
        grants = []
        for grant in policy.acl.grants:
            if grant.permission != "READ":
                grants.append(grant)
        count = 1
        for userid in read_acl:
            grant = Grant(
                id=userid, display_name=userid,
                permission='READ', type='CanonicalUser')
            grants.append(grant)
        policy.acl.grants = grants
        new_policy = policy.to_xml()
        if prev_policy != new_policy:
            bucket.set_xml_acl(new_policy)
            for key in bucket.get_all_keys():
                if key.get_acl().to_xml() != new_policy:
                    key.set_xml_acl(new_policy)

    def has_bucket_access(self, bucket, user_id):
        bucket = self.conn.get_bucket(bucket)
        for acl in bucket.get_acl().acl.grants:
            if acl.id == user_id:
                return True
        return False

    @handle_request
    def request(self, subject, method, payload=None, **kwargs):
        url = ('https://{server}:{port}'
               '/admin/{subject}'
               .format(server=self.server, subject=subject, port=self.port)
               )
        url = url + '?' + urlencode(dict(format='json', **kwargs))
        return requests.request(method, url, auth=self.auth, data=payload)

    def get_or_create_user(self, uid):
        r = self.get_user(uid)
        if r.status_code == 200:
            return r
        else:
            return self.create_user(uid)

    def get_user(self, uid):
        return self.request('user', 'GET', uid=uid)

    def create_user(self, uid, **kwargs):
        kwargs.update({'uid': uid, 'display-name': uid})
        return self.request('user', 'PUT', **kwargs)

    def delete_user(self, uid):
        return self.request('user', 'DELETE', uid=uid)

    def list_buckets(self):
        return self.request('bucket', 'GET')

    def get_or_create_bucket(
            self, access_key, secret_key, bucket_name, **kwargs):
        r = self.get_bucket(bucket_name)
        if r.status_code == 404:
            self.create_bucket(access_key, secret_key, bucket_name)

    def get_bucket(self, bucket):
        return self.request('bucket', 'GET', bucket=bucket)

    def create_bucket(self, access_key, secret_key, bucket_name):
        creds = dict(self.config)
        creds['aws_access_key_id'] = access_key
        creds['aws_secret_access_key'] = secret_key
        conn = connect_s3(**creds)
        return conn.create_bucket(bucket_name)

    def set_quota(self, uid, quota):
        return self.request(
            'user', 'PUT', quota=None,
            payload=json.dumps(quota), uid=uid)

    def create_key(self, uid, **kwargs):
        params = {'uid': uid, 'key': None}
        return self.request('user', 'PUT', **params)

    def remove_key(self, uid, access_key):
        params = {'uid': uid, 'access-key': access_key, 'key': None}
        return self.request('user', 'DELETE', **params)

    def remove_all_keys(self, uid):
        for key in self.get_user(uid).json()['keys']:
            self.remove_key(uid, key['access_key'])
