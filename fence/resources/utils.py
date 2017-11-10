from boto import connect_s3, connect_sts
from urllib import urlencode
from errors import InternalError
from boto.s3.acl import Grant
import settings
from django.shortcuts import redirect
from boto.exception import S3ResponseError
from keystoneclient.exceptions import NotFound
import json
from awsauth import S3Auth
import logging
from dateutil import parser
from keystoneclient.v3.client import Client
import requests
from boto.s3.connection import OrdinaryCallingFormat

logger = logging.getLogger(__name__)


def redirect_to_next(request):
    return redirect(request.session.get('next', settings.ROOT_PATH))


class KeystoneManager(object):
    def __init__(self):
        self.conn = Client(calling_format=OrdinaryCallingFormat(),
                           **settings.KEYSTONE_CREDS)
        self.role = self.conn.roles.find(name='_member_')

    def user_exist(self, username):
        try:
            if settings.KEYSTONE_USER_TYPE == 'user':
                self.conn.users.find(name=username)
                return True
            elif settings.KEYSTONE_USER_TYPE == 'group':
                self.conn.groups.find(name=username)
                return True
        except NotFound:
            return False

    def is_token_admin(self, token):
        try:
            result = self.conn.tokens.validate(token)
            if result['user']['name'] == 'admin':
                for role in result['roles']:
                    if role['name'] == 'admin':
                        return True
            return False
        except:
            return False

    def get_user_projects(self, username):
        '''
        Get all dbGap projects that a user have access to
        '''
        if settings.KEYSTONE_USER_TYPE == 'user':
            user = self.conn.users.find(name=username)
        else:
            user = self.conn.groups.find(name=username)
        resource = user.links['self']
        res = requests.get(
            resource+'/projects',
            headers={'X-Auth-Token': self.conn.auth_token})

        projects = []
        for project in res.json()['projects']:
            projects.append(project['name'])
        return projects


class S3Manager(object):
    def __init__(self):
        self.conn = connect_s3(**settings.S3)
        self.sts_conn = connect_sts(**settings.S3)
        self.DURATION = 3600*24

    def create_temp_token(self, username, buckets):
        bucket_policy = {
            'Action': ['s3:ListBucket'], 'Effect': 'Allow',
            'Resource': ["arn:aws:s3:::"+name for name in buckets]}
        object_policy = {
            'Action': ['s3:GetObject'], 'Effect': 'Allow',
            'Resource': ["arn:aws:s3:::"+name+"/*" for name in buckets]}
        policy = {'Statement': [bucket_policy, object_policy]}
        token = self.sts_conn.get_federation_token(
            username,
            self.DURATION,
            json.dumps(policy))
        return {'access_key': token.credentials.access_key,
                'secret_key': token.credentials.secret_key,
                'session_token': token.credentials.session_token,
                'expire': parser.parse(token.credentials.expiration)}

    def change_access(self, arn, bucket, action='add', prev_arn=''):
        bucket = self.conn.get_bucket(bucket)
        policy = None
        resource = 'arn:aws:s3:::' + bucket.name
        try:
            policy = json.loads(bucket.get_policy())
        except S3ResponseError as e:
            # If there is no policy set for this bucket, S3 will return 404
            if e.status == 404:
                policy = {}
        if policy is not None:
            if action == 'add':
                policy = self._add_policy(arn, policy, resource=resource)
                bucket.set_policy(json.dumps(policy))
            elif action == 'remove':
                policy_changed, policy = self._remove_policy(arn, policy)
                if policy_changed:
                    if not policy:
                        # If there is no more user in bucket policy,
                        # delete policy file
                        bucket.delete_policy()
                    else:
                        bucket.set_policy(json.dumps(policy))
            elif action == 'change':
                policy = self._add_policy(arn, policy, resource=resource)
                policy_changed, policy = self._remove_policy(prev_arn, policy)
                bucket.set_policy(json.dumps(policy))

        return policy

    def _add_policy(self, arn, policy, resource=""):
        if policy == {}:
            # This policy grant GetObject for all resources
            # within the bucket - resource/*
            # It also grant ListBucket for the bucket - resource
            allowed_resources = {
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Effect": "Allow",
                "Principal": {"AWS": arn},
                "Resource": [resource, resource+"/*"]}
            policy = {"Statement": [allowed_resources]}
        else:
            for statement in policy['Statement']:
                if 's3:GetObject' in statement['Action']:
                    try:
                        statement['Principal']['AWS'].append(arn)
                    except:
                        statement['Principal']['AWS'] =\
                            [statement['Principal']['AWS'], arn]
        return policy

    def _remove_policy(self, arn, policy):
        if policy == {}:
            return False, {}
        policy_changed = False
        for statement in policy['Statement']:
            if 's3:GetObject' in statement['Action']:
                if arn in statement['Principal']['AWS']:
                    policy_changed = True
                    principal = statement['Principal']
                    if type(principal['AWS']) == list:
                        principal['AWS'].remove(arn)
                    else:
                        policy['Statement'].remove(statement)
                    if len(principal['AWS']) == 1:
                        principal['AWS'] = principal['AWS'][0]

        if len(policy['Statement']) == 0:
            return policy_changed, {}
        return policy_changed, policy


def handle_request(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.exception("internal error")
            raise InternalError(e)
    return wrapper


class CephManager(object):
    def __init__(self):
        self.server = settings.CEPH['host']
        self.port = settings.CEPH['port']
        self.auth = S3Auth(settings.CEPH['aws_access_key_id'], settings.CEPH['aws_secret_access_key'],
            self.server+':'+str(self.port))
        self.conn = connect_s3(**settings.CEPH)

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
            grant = Grant(id=userid, display_name=userid, permission='READ', type='CanonicalUser')
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
        url = ('http://{server}:{port}'
               '/admin/{subject}'
               .format(server=self.server, subject=subject, port=self.port)
               )
        url = url + '?' + urlencode(dict(format='json', **kwargs))
        return requests.request(method, url, auth=self.auth, data=payload)

    def get_user(self, uid):
        return self.request('user', 'GET', uid=uid)

    def list_buckets(self):
        return self.request('bucket', 'GET')

    def create_user(self, uid, **kwargs):
        kwargs.update({'uid': uid, 'display-name': uid})
        return self.request('user', 'PUT', **kwargs)
        
    def set_quota(self, uid, quota):
        return self.request(
                'user', 'PUT', quota=None, payload=json.dumps(quota), uid=uid)

    def delete_user(self, uid):
        return self.request('user', 'DELETE', uid=uid)

    def remove_key(self, uid, access_key):
        params = {'uid': uid, 'access-key': access_key, 'key': None}
        return self.request('user', 'DELETE', **params)

    def remove_all_keys(self, uid):
        for key in self.get_user(uid).json()['keys']:
            self.remove_key(uid, key['access_key'])

    def create_key(self, uid, **kwargs):
        params = {'uid': uid, 'key': None}
        return self.request('user', 'PUT', **params)
