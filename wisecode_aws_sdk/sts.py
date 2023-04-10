"""Module for interacting with the STS service"""
import enum
import boto3
import typing
import logging

from wisecode_aws_sdk import utilities


logger = logging.getLogger("wisecode_aws_sdk.sts")


class WISEcodeAdminRole(enum.Enum):
    """Enum class for the main wisecode AWS account admin roles"""
    SANDBOX_NB = "arn:aws:iam::153982137511:role/sandbox-nb-admin"
    DEV = "arn:aws:iam::452376275135:role/dev-admin"
    PROD = "arn:aws:iam::364316551131:role/prod-admin"


def assume_admin_role(role_arn: str, session_name: str, duration: int = 3600) -> typing.Dict:
    """Assumes the provided aws role and returns the new session's aws security tokens

    :param role_arn: Arn value of the role to assume
    :type role_arn: str
    :param session_name: Name to assign the created session while assuming the given role
    :type session_name: str
    :param duration: Number of seconds for returned credentials to stay valid, default is 3600
    :type duration: int
    :return: Dictionary of the new session's aws security tokens
    :rtype: typing.Dict
    """
    utilities.remove_os_var(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"])
    sts = boto3.client("sts")
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=duration)

    return resp


def get_boto_session(sts_resp: dict, region_name: str = "us-east-2") -> boto3.Session:
    """Returns a boto session using the provided sts security tokens instead of the default (env vars or ~/.aws/config)

    :param sts_resp: Dictionary of sts security tokens for the role to use
    :type sts_resp: dict
    :param region_name: AWS region to use, defaults to "us-east-2"
    :type region_name: str, optional
    :return: A boto3 Session instance logged in with the given security tokens
    :rtype: boto3.Session
    """
    access_key = sts_resp["Credentials"]["AccessKeyId"]
    secret_access_key = sts_resp["Credentials"]["SecretAccessKey"]
    session_token = sts_resp["Credentials"]["SessionToken"]

    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        region_name=region_name
    )


def get_boto_resource(resource_name: str, sts_resp: dict, region_name: str = "us-east-2"):
    access_key = sts_resp["Credentials"]["AccessKeyId"]
    secret_access_key = sts_resp["Credentials"]["SecretAccessKey"]
    session_token = sts_resp["Credentials"]["SessionToken"]
    resource = boto3.resource(resource_name, 
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        region_name=region_name
    )

    return resource


def get_boto_client(client_name: str, sts_resp: dict, region_name: str = "us-east-2"):
    access_key = sts_resp["Credentials"]["AccessKeyId"]
    secret_access_key = sts_resp["Credentials"]["SecretAccessKey"]
    session_token = sts_resp["Credentials"]["SessionToken"]
    client = boto3.client(client_name, 
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        region_name=region_name
    )

    return client


# def assume_role_with_session(role_arn=None):
#     def sts_decorator(func):
#         sts = boto3.client("sts")

#         if client_name is not None:
#             client = 
#         @functools.wraps(func)
#         def sts_wrapper(*args, **kwargs):
#             try:
#                 value = func(*args, **kwargs)
#             except sts.exceptions.ExpiredTokenException as expired:
#                 logger.debug("Session token expired. Retrieving new session token...")


#             return value

#         return sts_wrapper
#     return sts_decorator

