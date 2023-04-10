import boto3
import botocore

def get_session(aws_access_key_id: str = None, aws_secret_access_key: str = None, aws_session_token: str = None, 
    region_name: str = None, botocore_session: botocore.session.Session = None, profile_name: str = None) -> boto3.Session:
    """Simple wrapper function that returns a boto3.Session class instance.
    A session stores configuration state and allows you to create service clients and resources.
    Full documentation can be found here, https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html#boto3.session.Session

    :param aws_access_key_id: AWS access key ID, defaults to None
    :type aws_access_key_id: str, optional
    :param aws_secret_access_key: AWS secret access key, defaults to None
    :type aws_secret_access_key: str, optional
    :param aws_session_token: AWS temporary session token, defaults to None
    :type aws_session_token: str, optional
    :param region_name: Default region when creating new connections, defaults to None
    :type region_name: str, optional
    :param botocore_session: Use this Botocore session instead of creating a new default one, defaults to None
    :type botocore_session: botocore.session.Session, optional
    :param profile_name: The name of a profile to use. If not given, then the default profile is used, defaults to None
    :type profile_name: str, optional
    :return: A boto3.Session class instance
    :rtype: boto3.Session
    """
    return boto3.Session(
        aws_access_key_id=aws_access_key_id, 
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token, 
        region_name=region_name, 
        botocore_session=botocore_session,
        profile_name=profile_name
    )
