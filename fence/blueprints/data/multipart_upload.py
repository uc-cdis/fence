import boto3
import botocore
from retry.api import retry_call

from cdispyutils.hmac4 import generate_aws_presigned_url
from cdislogging import get_logger
from fence.errors import InternalError

MAX_TRIES = 5

logger = get_logger(__name__)


def initilize_multipart_upload(bucket, key, credentials):
    """
    Initialize multipart upload

    Args:
        bucket(str): bucket name
        key(str): object key
        credentials(dict): credential dictionary

    Returns:
        UploadId(str): uploadId
    """
    session = boto3.Session(
        aws_access_key_id=credentials["aws_access_key_id"],
        aws_secret_access_key=credentials["aws_secret_access_key"],
        aws_session_token=credentials.get("aws_session_token"),
    )
    s3client = session.client("s3")

    try:
        multipart_upload = retry_call(
            s3client.create_multipart_upload,
            fkwargs={"Bucket": bucket, "Key": key},
            tries=MAX_TRIES,
            jitter=10,
        )
    except botocore.exceptions.ClientError as error:
        logger.error(
            "Error when create multiple part upload for object with uuid {}. Detail {}".format(
                key, error
            )
        )
        raise InternalError("Can not initilize multipart upload for {}".format(key))

    return multipart_upload.get("UploadId")


def complete_multipart_upload(bucket, key, credentials, uploadId, parts):
    """
    Complete multipart upload.
    Raise exception if something wrong happens; otherwise success

    Args:
        bucket(str): bucket name
        key(str): object key or `GUID/filename`
        credentials(dict): aws credentials
        uploadId(str): upload id of the current upload
        parts(list(set)): List of part infos
                [{"Etag": "1234567", "PartNumber": 1}, {"Etag": "4321234", "PartNumber": 2}]

    Return:
        None
    """
    session = boto3.Session(
        aws_access_key_id=credentials["aws_access_key_id"],
        aws_secret_access_key=credentials["aws_secret_access_key"],
        aws_session_token=credentials.get("aws_session_token"),
    )
    s3client = session.client("s3")

    try:
        retry_call(
            s3client.complete_multipart_upload,
            fkwargs={
                "Bucket": bucket,
                "Key": key,
                "MultipartUpload": {"Parts": parts},
                "UploadId": uploadId,
            },
            tries=MAX_TRIES,
            jitter=10,
        )
    except botocore.exceptions.ClientError as error:
        logger.error(
            "Error when completing multiple part upload for object with uuid {}. Detail {}".format(
                key, error
            )
        )
        raise InternalError(
            "Can not complete multipart upload for {}. Detail {}".format(key, error)
        )


def generate_presigned_url_for_uploading_part(
    bucket, key, credentials, uploadId, partNumber, region, expires
):
    """
    Generate presigned url for uploading object part given uploadId and part number

    Args:
        bucket(str): bucket
        key(str): key
        credentials(dict): dictionary of aws credentials
        uploadId(str): uploadID of the multipart upload
        partNumber(int): part number
        region(str): bucket region
        expires(int): expiration time
    
    Returns:
        presigned_url(str)
    """

    url = "https://{}.s3.amazonaws.com/{}".format(bucket, key)
    additional_signed_qs = {"partNumber": str(partNumber), "uploadId": uploadId}

    try:
        return generate_aws_presigned_url(
            url, "PUT", credentials, "s3", region, expires, additional_signed_qs
        )
    except Exception as e:
        raise InternalError(
            "Can not generate presigned url for part number {} of key {}. Detail {}".format(
                partNumber, key, e
            )
        )
