from boto3 import client
from boto3.exceptions import Boto3Error
from fence.errors import UserError, InternalError, UnavailableError
import uuid

class BotoManager(object):
    def __init__(self, config, logger):
        self.sts_client = client('sts', **config)
        self.s3_client = client('s3', **config)
        self.logger = logger
        self.ec2 = None
        self.iam = None

    def assume_role(self, role_arn, duration_seconds, config=None):
        try:
            if config and config.has_key('aws_access_key_id'):
                self.sts_client = client('sts', **config)
            session_name_postfix = uuid.uuid4()
            return self.sts_client.assume_role(
                RoleArn=role_arn, DurationSeconds=duration_seconds,
                RoleSessionName='{}-{}'.format("gen3", session_name_postfix))
        except Boto3Error as ex:
            self.logger.exception(ex)
            raise InternalError("Fail to assume role: {}".format(ex.message))
        except Exception as ex:
            self.logger.exception(ex)
            raise UnavailableError("Fail to reach AWS: {}".format(ex.message))

    def presigned_url(self, bucket, key, expires, config, method='get_object'):
        if config.has_key('aws_access_key_id'):
            self.s3_client = client('s3', **config)
        if method not in ['get_object', 'put_object']:
            raise UserError('method {} not allowed'.format(method))
        if expires is None:
            expires = 1800
        elif expires > 3600 * 24:
            expires = 3600 * 24

        url = self.s3_client.generate_presigned_url(
            ClientMethod=method,
            Params={
                'Bucket': bucket,
                'Key': key
            } if method == 'get_object' else {
                'Bucket': bucket,
                'Key': key,
                'ServerSideEncryption': 'AES256'
            },
            ExpiresIn=expires
        )
        return url

    def get_bucket_region(self, bucket, config):
        try:
            if config.has_key('aws_access_key_id'):
                self.s3_client = client('s3', **config)
            response = self.s3_client.get_bucket_location(Bucket=bucket)
            region = response.get('LocationConstraint')
        except Boto3Error as ex:
            self.logger.exception(ex)
            raise InternalError("Fail to get bucket region: {}".format(ex.message))
        except Exception as ex:
            self.logger.exception(ex)
            raise UnavailableError("Fail to reach AWS: {}".format(ex.message))
        if region is None:
            return 'us-east-1'
        return region

    def get_all_groups(self, list_group_name):
        '''
        Get all group listed in the list_group_name.
        If group does not exist, add as new group and include in the return list
        :param list_group_name:
        :return:
        '''
        try:
            groups = self.get_user_group(list_group_name)
            if len(groups) < len(list_group_name):
                for group_name in list_group_name:
                    if group_name not in groups:
                        groups[group_name] = self.create_user_group(group_name)
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to create list of groups: {}".format(ex.message))
        return groups

    def add_user_to_group(self, groups, username):
        '''
        Add user to the list of group which have association membership.
        :param groups:
        :param username:
        :return:
        '''
        try:
            for group in groups.values():
                self.iam.add_user_to_group(GroupName=group["GroupName"], UserName=username)
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to add user to group: {}".format(ex.message))

    def get_user_group(self, group_names):
        try:
            groups = self.iam.list_groups()["Groups"]
            res = {}
            for group in groups:
                if group["GroupName"] in group_names:
                    res[group["GroupName"]] = group
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to get list of groups {}: {}".format(group_names, ex.message))
        return res

    def create_user_group(self, group_name, path=None):
        try:
            group = self.iam.create_group(GroupName=group_name)["Group"]
            self.__create_policy__(group_name, self.__get_policy_document_by_group_name__(group_name))
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to create group {}: {}".format(group_name, ex.message))
        return group

    def __get_policy_document_by_group_name__(self, group_name):
        '''
        Getting policy document from config file and replace with actual value (same as project name)
        :param group_name:
        :return:
        '''
        pass

    def __fill_with_new_value__(self, document, value):
        pass

    def __create_policy__(self, policy_name, policy_document, path=None, description=None):
        '''
        Create policy with name and policies specified in policy_document.
        :param policy_name: Name of policy in AWS.
        :param policy_document: Document specified the policy rule.
        :param path:
        :param description:
        :return:
        '''
        try:
            aws_kwargs = dict(Path=path, Description=description)
            aws_kwargs = {k: v for k, v in aws_kwargs.items() if v is not None}
            policy = self.iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_document, **aws_kwargs
            )
            self.iam.attach_group_policy(GroupName=policy_name, PolicyArn=policy['Policy']['Arn'])
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to create policy: {}".format(ex.message))
        return policy
