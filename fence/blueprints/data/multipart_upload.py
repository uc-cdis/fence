import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from retry.api import retry_call

from cdispyutils.config import get_value
from cdislogging import get_logger
from gen3cirrus import AwsService
from fence.config import config
from fence.errors import InternalError

MAX_TRIES = 5

logger = get_logger(__name__)


def initialize_multipart_upload(bucket_name, key, credentials):
    """
    Initialize multipart upload

    Args:
        bucket(str): bucket name
        key(str): object key
        credentials(dict): credential dictionary

    Returns:
        UploadId(str): uploadId
    """
    s3_buckets = get_value(
        config, "S3_BUCKETS", InternalError("S3_BUCKETS not configured")
    )
    bucket = s3_buckets.get(bucket_name)

    url = ""
    if bucket.get("endpoint_url"):
        url = bucket["endpoint_url"]

    session = boto3.Session(
        aws_access_key_id=credentials["aws_access_key_id"],
        aws_secret_access_key=credentials["aws_secret_access_key"],
        aws_session_token=credentials.get("aws_session_token"),
    )
    s3client = None
    if url:
        s3client = session.client("s3", endpoint_url=url)
    else:
        s3client = session.client("s3")

    try:
        multipart_upload = retry_call(
            s3client.create_multipart_upload,
            fkwargs={"Bucket": bucket_name, "Key": key},
            tries=MAX_TRIES,
            jitter=10,
        )
    except ClientError as error:
        logger.error(
            "Error when create multiple part upload for object with uuid {}. Detail {}".format(
                key, error
            )
        )
        raise InternalError("Can not initilize multipart upload for {}".format(key))

    return multipart_upload.get("UploadId")


def complete_multipart_upload(bucket_name, key, credentials, upload_id, parts):
    """
    Complete multipart upload.
    Raise exception if something wrong happens; otherwise success

    Args:
        bucket(str): bucket name
        key(str): object key or `GUID/filename`
        credentials(dict): aws credentials
        upload_id(str): upload id of the current upload
        parts(list(set)): List of part infos
                [{"Etag": "1234567", "PartNumber": 1}, {"Etag": "4321234", "PartNumber": 2}]

    Return:
        None
    """
    s3_buckets = get_value(
        config, "S3_BUCKETS", InternalError("S3_BUCKETS not configured")
    )
    bucket = s3_buckets.get(bucket_name)

    url = ""
    if bucket.get("endpoint_url"):
        url = bucket["endpoint_url"]

    session = boto3.Session(
        aws_access_key_id=credentials["aws_access_key_id"],
        aws_secret_access_key=credentials["aws_secret_access_key"],
        aws_session_token=credentials.get("aws_session_token"),
    )
    s3client = None
    if url:
        s3client = session.client("s3", endpoint_url=url)
    else:
        s3client = session.client("s3")

    try:
        retry_call(
            s3client.complete_multipart_upload,
            fkwargs={
                "Bucket": bucket_name,
                "Key": key,
                "MultipartUpload": {"Parts": parts},
                "UploadId": upload_id,
            },
            tries=MAX_TRIES,
            jitter=10,
        )
    except ClientError as error:
        logger.error(
            "Error when completing multiple part upload for object with uuid {}. Detail {}".format(
                key, error
            )
        )
        raise InternalError(
            "Can not complete multipart upload for {}. Detail {}".format(key, error)
        )


def generate_presigned_url_for_uploading_part(
    bucket_name, key, credentials, upload_id, part_number, region, expires
):
    """
    Generate presigned url for uploading object part given uploadId and part number

    Args:
        bucket(str): bucket
        key(str): key
        credentials(dict): dictionary of aws credentials
        upload_id(str): uploadID of the multipart upload
        part_number(int): part number
        region(str): bucket region
        expires(int): expiration time

    Returns:
        presigned_url(str)
    """
    s3_buckets = get_value(
        config, "S3_BUCKETS", InternalError("S3_BUCKETS not configured")
    )
    bucket = s3_buckets.get(bucket_name)

    try:
        s3client = boto3.client(
            "s3",
            aws_access_key_id=credentials["aws_access_key_id"],
            aws_secret_access_key=credentials["aws_secret_access_key"],
            region_name=region,
            config=Config(s3={"addressing_style": "path"}, signature_version="s3v4"),
        )
        cirrus_aws = AwsService(s3client)

        presigned_url = cirrus_aws.multipart_upload_presigned_url(
            bucket, key, expires, upload_id, part_number
        )

        return presigned_url
    except Exception as e:
        raise InternalError(
            "Can not generate presigned url for part number {} of key {}. Detail {}".format(
                part_number, key, e
            )
        )
