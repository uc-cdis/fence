"""Functions for interaction with the AWS Secrets Manager service"""

import json
import typing
import boto3


def get_json_secret_value(secret_name: str, client=None, region: str ="us-east-2") -> typing.Dict:
    """Retreives the AWS Secrets Manager secret's json content and returns it as a dictionary

    :param secret_name: Name of the secret to retrieve
    :type secret_name: str
    :param client: boto3 secretsmanager client instance, defaults to None
    :type client: SecretsManager.Client, optional
    :param region: AWS region secret is located in, defaults to "us-east-2"
    :type region: str, optional
    :return: Dictionary of the secret's JSON content
    :rtype: typing.Dict
    """
    
    if client is None:
        client = boto3.client("secretsmanager", region_name=region)
        
    secret = client.get_secret_value(SecretId=secret_name)

    return json.loads(secret["SecretString"])