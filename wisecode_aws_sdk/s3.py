"""Module containing functions that help with interaction with the AWS S3 service"""
import io
import os
import sys
import gzip
import boto3
import shutil
import typing
import pathlib
import tempfile
import threading
import concurrent.futures
from botocore.client import Config
from boto3.s3.transfer import TransferConfig, MB, KB


class ProgressPercentage(object):
    """Class that reports the progress of an S3 file upload when set as the 
    Callback parameter in an upload_file func call. Taken from the boto3
    S3 documentation page.
    """

    def __init__(self, filename: str):
        """Initialize ProgressPercentage for a given file

        :param filename: Full filepath to the file being uploaded to S3
        :type filename: str
        """
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        # To simplify we'll assume this is hooked up
        # to a single filename.
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._size) * 100
            sys.stdout.write(
                "\r%s  %s / %s  (%.2f%%)" % (
                    self._filename, self._seen_so_far, self._size,
                    percentage))
            sys.stdout.flush()


def _get_s3_resource(session: boto3.Session = None, config: Config = None):
    """Helper function for s3 module that returns a boto3 s3 service resource object instance.
    Will construct a default boto3 Session if none is provided.

    :param session: boto3 Session instance, defaults to None
    :type session: boto3.Session, optional
    :param config: boto3.client Config instance that allows more avanced configuration of Botocore clients, defaults to None
    :type config: boto3.client.Config
    :return: A boto3 S3 Resource instance
    :rtype: S3.ServiceResource
    """
    if not session:
        session = boto3._get_default_session()

    return session.resource("s3", config=config)


def get_s3_object(bucket_name: str, key: str, session: boto3.Session = None) -> str:
    """Downloads requested S3 object from provided bucket and returns it as a string

    :param bucket_name: S3 bucket name where object is located
    :type bucket_name: str
    :param key: S3 object key to download
    :type key: str
    :param session: boto3 Session instance to use when accessing S3, defaults to None
    :type session: boto3.Session, optional
    :return: Content of the S3 object as a string
    :rtype: str
    """
    s3 = _get_s3_resource(session=session)
    bucket = s3.Bucket(bucket_name)

    return bucket.Object(key).get()["Body"].read().decode("utf-8")


def get_s3_objects(bucket_name: str, prefix: str, session: boto3.Session = None) -> typing.Dict[str, str]:
    """Downloads all objects found in provided S3 bucket name with given prefix and returns them 
    in a dictionary with the S3 object keys and the keys and the object body's as strings as the values.

    :param bucket_name: S3 bucket name to download objects from
    :type bucket_name: str
    :param prefix: Prefix to search for S3 objects with
    :type prefix: str
    :param session: boto3 Session instance to use when accessing S3, defaults to None
    :type session: boto3.Session, optional
    :return: Dictionary with key = object key and value = object body as a string 
    :rtype: typing.Dict[str, str]
    """
    s3 = _get_s3_resource(session=session)
    bucket = s3.Bucket(bucket_name)
    
    return {obj.key: obj.get()["Body"].read().decode("utf-8") for obj in bucket.objects.filter(Prefix=prefix)}


def download_file(bucket_name: str, key: str, filename: pathlib.Path, session: boto3.Session = None, decompress: bool = False) -> pathlib.Path:
    """Downloads the specifed S3 object to a file on the local filesystem with the provided filename. Can optionally decompress a .gz object.

    :param bucket_name: S3 bucket name to download objects from
    :type bucket_name: str
    :param key: S3 object key to download
    :type key: str
    :param filename: File to create on local disk
    :type filename: pathlib.Path
    :param session: boto3 Session instance to use when accessing S3, defaults to None
    :type session: boto3.Session, optional
    :param decompress: Set to True to decompresss a gzip file before writing to local disk, defaults to False
    :type decompress: bool, optional
    :return: a Path object to the newly created file
    :rtype: pathlib.Path
    """
    s3 = _get_s3_resource(session=session)
    bucket = s3.Bucket(bucket_name)
    obj = bucket.Object(key)

    with open(filename, "wb") as f:
        obj.download_fileobj(f)

    if decompress:      
        # remove .gz extension if file has one
        if str(filename).split(".")[-1] == "gz":
            newfile = pathlib.Path(str(filename)[:-3])
        else:
            newfile = pathlib.Path(str(filename) + "(1)")
        
        with gzip.open(filename, "rb") as r, open(newfile, "wb") as w:
            w.write(r.read())

        filename.unlink()
        filename = newfile

    return pathlib.Path(filename)


def download_files(bucket_name: str, objects: typing.Dict[str, pathlib.Path], session: boto3.Session = None, decompress: bool = False, max_workers: int = 10) -> typing.Dict[str, pathlib.Path]:
    """Downloads the specifed S3 objects to the given files on local disk. Can optionally decompress .gz objects.

    :param bucket_name: S3 bucket name to download objects from
    :type bucket_name: str
    :param objects: Dictionary of key name to pathlib.Path files key value pairs for the keys to download
    :type objects: typing.Dict[str, pathlib.Path]
    :param session: boto3 Session instance to use when accessing S3, defaults to None
    :type session: boto3.Session, optional
    :param decompress: Set to True to decompresss gzip files before writing to local disk, defaults to False
    :type decompress: bool, optional
    :param max_workers: Number of threads to use during the download, defaults to 10
    :type max_workers: int, optional
    :return: Dictionary with {object key: new file} key value pairs
    :rtype: typing.Dict[str, pathlib.Path]
    """
    results = {}

    if session:
        creds = session.get_credentials()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        download_futures = {
            executor.submit(
                download_file, 
                bucket_name, 
                key, 
                filename, 
                session=boto3.Session(
                    aws_access_key_id=creds.access_key,
                    aws_secret_access_key=creds.secret_key,
                    aws_session_token=creds.token,
                    region_name=session.region_name()
                ) if session else boto3.Session(), 
                decompress=decompress
            ): key for key, filename in objects.items()
        }

        for future in concurrent.futures.as_completed(download_futures):
            key = download_futures[future]
            results[key] = future.result()
        
        return results


def put_s3_object(bucket_name: str, key: str, body: str, session: boto3.Session = None) -> typing.Dict:
    """Uploads the provided string to the given S3 bucket name with the provided key name. Returns the 
    S3 service response.

    :param bucket_name: S3 bucket name to upload data to
    :type bucket_name: str
    :param key: Key name to set as the uploaded data's key for the resulting S3 object
    :type key: str
    :param body: Data to upload
    :type body: str
    :param session: boto3 Session instance to use when accessing S3, defaults to None
    :type session: boto3.Session, optional
    :return: The S3 service response containing some metadata
    :rtype: typing.Dict
    """
    s3 = _get_s3_resource(session=session)
    bucket = s3.Bucket(bucket_name)
    obj = bucket.Object(key)
    resp = obj.put(Body=body)

    return resp


def put_s3_objects(bucket_name: str, objects: typing.Dict[str, str], session: boto3.Session = None, max_workers: int = 10) -> typing.Dict[str, typing.Dict]:
    """Uploads data to the provided S3 bucket as multiple objects. The data is provided in a dictionary where the key is the desired S3 object
    key and the value is the data as a string to upload for that key. Default is to use multiple threads to preform the uploads. Set max_workers
    to 1 to disable the multithreading, increasing max_workers will increase the number of threads avaible for use. Each thread will process one
    object.

    :param bucket_name: S3 bucket name to upload data to
    :type bucket_name: str
    :param objects: Dictionary of keys to use and data to upload for those keys
    :type objects: typing.Dict[str, str]
    :param session: boto3 Session instance to use when accessing S3, defaults to None
    :type session: boto3.Session, optional
    :param max_workers: Number of threads to use during the upload, defaults to 10
    :type max_workers: int, optional
    :return: Dictionary of the object key to S3 service's response for its upload
    :rtype: typing.Dict[str, typing.Dict]
    """
    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures_to_key = {
            executor.submit(put_s3_object, bucket_name, key, body, session=boto3.Session()): key for key, body in objects.items()
        }

        for future in concurrent.futures.as_completed(futures_to_key):
            key = futures_to_key[future]
            results[key] = future.result()

    return results


def upload_file(bucket_name: str, key: str, filename: pathlib.Path, session: boto3.Session = None, compress: bool = False, in_memory: bool = False,
    tconfig: TransferConfig = None, sconfig: Config = None, is_large_file: bool = True) -> None:
    """Uploads given file to the specified S3 bucket with the given key. Can optionally gzip the file before upload.

    :param bucket_name: S3 bucket name to upload data to
    :type bucket_name: str
    :param key: Key name to set as the uploaded data's key for the resulting S3 object
    :type key: str
    :param filename: Full file path to file to upload
    :type filename: pathlib.Path
    :param session: boto3 Session instance to use when accessing S3, defaults to None
    :type session: boto3.Session, optional
    :param compress: Set to true to gzip the file before uploading to S3, defaults to False
    :type compress: bool, optional
    :param in_memory: Set to true so compression is performed in memory with no intermedate file, defaults to False
    :type compress: bool, optional
    :param tconfig: A boto3.s3.transfer.TransferConfig object that will be used to set the upload transfer configs, defaults to None. None will cause the upload to use the default upload configs, read more about TransferConfig here https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3.html
    :type tconfig: boto3.s3.transfer.TransferConfig, optional
    :param sconfig: boto3.client Config instance that allows more avanced configuration of Botocore clients to alter session connection, defaults to None
    :type sconfig: boto3.client.Config, optional
    :param is_large_file: Set to true to use preset boto3.s3.transfer.TransferConfig options that are better for large file uploads, defaults to False
    :type is_large_file: bool
    """    

    if is_large_file:
        # set session and transfer configs to work better for large files
        sconfig = Config(
            connect_timeout=120,
            retries={"max_attempts": 0},
            read_timeout=120,
            max_pool_connections=50
        )
        s3 = _get_s3_resource(session=session, config=sconfig)  
        tconfig = TransferConfig(
            multipart_threshold=1024*MB,
            max_concurrency=50,
            multipart_chunksize=1024*MB,
            use_threads=True,
            io_chunksize=128*MB
        )
    elif tconfig is None:
        # default session and transfer configs work well for small files so just use those
        tconfig = TransferConfig()

    if sconfig is None:
        # default client config for session
        sconfig = Config()

    s3 = _get_s3_resource(session=session, config=sconfig)   
    b = s3.Bucket(bucket_name)   

    if compress:
        if in_memory:
            gz_data = io.BytesIO()
        else:
            gz_data = tempfile.TemporaryFile()

        with open(filename, "rb") as f, gzip.GzipFile(fileobj=gz_data, mode="wb") as gz:
            shutil.copyfileobj(f, gz)
        
        gz_data.seek(0)
        o = b.Object(key + ".gz")
        o.upload_fileobj(gz_data, Config=tconfig, Callback=ProgressPercentage(filename))
        gz_data.close()
    else:
        o = b.Object(key)
        o.upload_file(str(filename), Config=tconfig, Callback=ProgressPercentage(filename))

        
def upload_files(bucket_name: str, objects: typing.Dict[str, object], session: boto3.Session = None, compress: bool = False, 
    max_workers: int = 10, in_memory: bool = False) -> None:
    """Uploads a group of files to the specified S3 bucket with the given keys. Can optionally gzip the files before upload.
    Files are passed to function in a dictionary where the desired S3 key is the key and the value is a pathlib.Path object of the file 
    to load. Further config options can be passed to each file upload by replacing the pathlib.Path value with a dictionary with the keys,
    "file", "tconfig", "sconfig", "is_large_file". "File" is the pathlib.Path object for the file to upload. "tconfig" is optional and would pass a
    boto3.s3.transfer.TransferConfig object to the s3 upload for that file. "sconfig" is optional and would pass a boto3.client.Config
    object to the s3 client session. "is_large_file" is also optional and would cause the s3 upload to use TransferConfig options that work 
    better for large files.

    :param bucket_name: S3 bucket name to upload data to
    :type bucket_name: str
    :param objects: Dictionary of key name to pathlib.Path files key value pairs for the files to load
    :type objects: typing.Dict[str, pathlib.Path]
    :param session: boto3 Session instance to use when accessing S3, defaults to None
    :type session: boto3.Session, optional
    :param compress: Set to true to gzip the files before uploading to S3, defaults to False
    :type compress: bool, optional
    :param max_workers: Number of threads to use during the upload, defaults to 10
    :type max_workers: int, optional
    :param in_memory: Set to true so compression is performed in memory with no intermedate file, defaults to False
    :type compress: bool, optional
    """
    if session:
        creds = session.get_credentials()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        upload_futures = []

        for key, value in objects.items():
            if isinstance(value, pathlib.Path):
                filename = value
                tconfig = None
                is_large_file = False
                sconfig = None
            else:
                filename = value["file"]
                tconfig = value.get("tconfig")
                is_large_file = value.get("is_large_file", False)
                sconfig = value.get("sconfig")

            upload_futures.append(executor.submit(
                upload_file, 
                bucket_name, 
                key, 
                filename, 
                session=boto3.Session(
                    aws_access_key_id=creds.access_key,
                    aws_secret_access_key=creds.secret_key,
                    aws_session_token=creds.token,
                    region_name=session.region_name
                ) if session else boto3.Session(),
                compress=compress,
                in_memory=in_memory,
                tconfig=tconfig,
                sconfig=sconfig,
                is_large_file=is_large_file
            ))

        results = [future.result() for future in concurrent.futures.as_completed(upload_futures)]
