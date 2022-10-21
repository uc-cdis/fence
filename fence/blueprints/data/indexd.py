import re
import time
import json
from urllib.parse import urlparse, ParseResult, urlunparse
from datetime import datetime, timedelta

from sqlalchemy.sql.functions import user
from cached_property import cached_property
import cirrus
from cirrus import GoogleCloudManager
from cdislogging import get_logger
from cdispyutils.config import get_value
from cdispyutils.hmac4 import generate_aws_presigned_url
import flask
from flask_sqlalchemy_session import current_session
import requests
from azure.storage.blob import (
    BlobServiceClient,
    ResourceTypes,
    AccountSasPermissions,
    generate_blob_sas,
)
from fence import auth

from fence.auth import (
    get_jwt,
    current_token,
    login_required,
    set_current_token,
    validate_request,
    JWTError,
)
from fence.config import config
from fence.errors import (
    Forbidden,
    InternalError,
    NotFound,
    NotSupported,
    Unauthorized,
    UnavailableError,
)
from fence.resources.google.utils import (
    get_or_create_primary_service_account_key,
    create_primary_service_account_key,
    get_or_create_proxy_group_id,
    get_google_app_creds,
    give_service_account_billing_access_if_necessary,
)
from fence.resources.ga4gh.passports import sync_gen3_users_authz_from_ga4gh_passports
from fence.utils import get_valid_expiration_from_request
from . import multipart_upload
from ...models import AssumeRoleCacheAWS, query_for_user, query_for_user_by_id
from ...models import AssumeRoleCacheGCP

logger = get_logger(__name__)

ACTION_DICT = {
    "s3": {"upload": "PUT", "download": "GET"},
    "gs": {"upload": "PUT", "download": "GET"},
    "az": {"upload": "PUT", "download": "GET"},
}

SUPPORTED_PROTOCOLS = ["s3", "http", "ftp", "https", "gs", "az"]
SUPPORTED_ACTIONS = ["upload", "download"]
ANONYMOUS_USER_ID = "-1"
ANONYMOUS_USERNAME = "anonymous"


def get_signed_url_for_file(
    action,
    file_id,
    file_name=None,
    requested_protocol=None,
    ga4gh_passports=None,
    db_session=None,
    bucket=None,
):
    requested_protocol = requested_protocol or flask.request.args.get("protocol", None)
    r_pays_project = flask.request.args.get("userProject", None)
    db_session = db_session or current_session

    # default to signing the url
    force_signed_url = True
    no_force_sign_param = flask.request.args.get("no_force_sign")
    if no_force_sign_param and no_force_sign_param.lower() == "true":
        force_signed_url = False

    if ga4gh_passports and not config["GA4GH_PASSPORTS_TO_DRS_ENABLED"]:
        raise NotSupported(
            "Using GA4GH Passports as a means of authentication and authorization "
            "is not supported by this instance of Gen3."
        )

    users_from_passports = {}
    if ga4gh_passports:
        # users_from_passports = {"username": Fence.User}
        users_from_passports = sync_gen3_users_authz_from_ga4gh_passports(
            ga4gh_passports, db_session=db_session
        )

    # add the user details to `flask.g.audit_data` first, so they are
    # included in the audit log if `IndexedFile(file_id)` raises a 404
    if users_from_passports:
        if len(users_from_passports) > 1:
            logger.warning(
                "audit service doesn't support multiple users for a "
                "single request yet, so just log userinfo here"
            )
            for username, user in users_from_passports.items():
                audit_data = {
                    "username": username,
                    "sub": user.id,
                }
                logger.info(
                    f"passport with multiple user ids is attempting data access. audit log: {audit_data}"
                )
        else:
            username, user = next(iter(users_from_passports.items()))
            flask.g.audit_data = {
                "username": username,
                "sub": user.id,
            }
    else:
        auth_info = _get_auth_info_for_id_or_from_request(
            sub_type=int, db_session=db_session
        )
        flask.g.audit_data = {
            "username": auth_info["username"],
            "sub": auth_info["user_id"],
        }

    indexed_file = IndexedFile(file_id)
    default_expires_in = config.get("MAX_PRESIGNED_URL_TTL", 3600)
    expires_in = get_valid_expiration_from_request(
        max_limit=default_expires_in,
        default=default_expires_in,
    )

    prepare_presigned_url_audit_log(requested_protocol, indexed_file)
    signed_url, authorized_user_from_passport = indexed_file.get_signed_url(
        requested_protocol,
        action,
        expires_in,
        force_signed_url=force_signed_url,
        r_pays_project=r_pays_project,
        file_name=file_name,
        users_from_passports=users_from_passports,
        bucket=bucket,
    )

    # a single user from the list was authorized so update the audit log to reflect that
    # users info
    if authorized_user_from_passport:
        flask.g.audit_data = {
            "username": authorized_user_from_passport.username,
            "sub": authorized_user_from_passport.id,
        }

    # increment counter for gen3-metrics
    counter = flask.current_app.prometheus_counters.get("pre_signed_url_req")
    if counter:
        counter.labels(requested_protocol).inc()

    return {"url": signed_url}


def prepare_presigned_url_audit_log(protocol, indexed_file):
    """
    Store in `flask.g.audit_data` the data needed to record an audit log.
    """
    resource_paths = indexed_file.index_document.get("authz", [])
    if not resource_paths:
        # fall back on ACL
        resource_paths = indexed_file.index_document.get("acl", [])
    if not protocol and indexed_file.indexed_file_locations:
        protocol = indexed_file.indexed_file_locations[0].protocol
    flask.g.audit_data["resource_paths"] = resource_paths
    flask.g.audit_data["protocol"] = protocol


class BlankIndex(object):
    """
    A blank record in indexd, to use for the data upload flow.

    See docs on data upload flow for further details:

        https://github.com/uc-cdis/cdis-wiki/tree/master/dev/gen3/data_upload
    """

    def __init__(
        self, uploader=None, file_name=None, logger_=None, guid=None, authz=None
    ):
        self.logger = logger_ or logger
        self.indexd = (
            flask.current_app.config.get("INDEXD")
            or flask.current_app.config["BASE_URL"] + "/index"
        )

        # allow passing "" empty string to signify you do NOT want
        # uploader to be populated. If nothing is provided, default
        # to parsing from token
        if uploader == "":
            self.uploader = None
        elif uploader:
            self.uploader = uploader
        else:
            self.uploader = current_token["context"]["user"]["name"]

        self.file_name = file_name
        self.authz = authz

        # if a guid is not provided, this will create a blank record for you
        self.guid = guid or self.index_document["did"]

    @cached_property
    def index_document(self):
        """
        Get the record from indexd for this index.

        Return:
            dict:
                response from indexd (the contents of the record), containing ``guid``
                and ``url``
        """
        index_url = self.indexd.rstrip("/") + "/index/blank/"
        params = {"uploader": self.uploader, "file_name": self.file_name}

        # if attempting to set record's authz field, need to pass token
        # through
        if self.authz:
            params["authz"] = self.authz
            token = get_jwt()

            auth = None
            headers = {"Authorization": f"bearer {token}"}
            logger.info("passing users authorization header to create blank record")
        else:
            logger.info("using indexd basic auth to create blank record")
            auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
            headers = {}

        indexd_response = requests.post(
            index_url, json=params, headers=headers, auth=auth
        )
        if indexd_response.status_code not in [200, 201]:
            try:
                data = indexd_response.json()
            except ValueError:
                data = indexd_response.text
            self.logger.error(
                "could not create new record in indexd; got response: {}".format(data)
            )
            raise InternalError(
                "received error from indexd trying to create blank record"
            )
        document = indexd_response.json()
        guid = document["did"]
        self.logger.info(
            "created blank index record with GUID {} for upload".format(guid)
        )
        return document

    def make_signed_url(self, file_name, protocol=None, expires_in=None, bucket=None):
        """
        Works for upload only; S3 or Azure Blob Storage only
        (only supported case for data upload flow currently).

        Args:
            file_name (str)
            expires_in (int)

        Return:
            S3IndexedFileLocation or AzureBlobStorageIndexedFileLocation
        """

        # check if azure, and default to S3

        if protocol == "az":
            try:
                container = flask.current_app.config["AZ_BLOB_CONTAINER_URL"]
            except KeyError:
                raise InternalError(
                    "fence not configured with data upload container; can't create signed URL"
                )
            container_url = "{}/{}/{}".format(container, self.guid, file_name)

            url = AzureBlobStorageIndexedFileLocation(container_url).get_signed_url(
                "upload", expires_in
            )
        else:
            if not bucket:
                try:
                    bucket = flask.current_app.config["DATA_UPLOAD_BUCKET"]
                except KeyError:
                    raise InternalError(
                        "fence not configured with data upload bucket; can't create signed URL"
                    )

            self.logger.debug("Attemping to upload to bucket '{}'".format(bucket))
            s3_url = "s3://{}/{}/{}".format(bucket, self.guid, file_name)
            url = S3IndexedFileLocation(s3_url).get_signed_url("upload", expires_in)

        self.logger.info(
            "created presigned URL to upload file {} with ID {}".format(
                file_name, self.guid
            )
        )

        return url

    @staticmethod
    def init_multipart_upload(key, expires_in=None):
        """
        Initilize multipart upload given key

        Args:
            key(str): object key

        Returns:
            uploadId(str)
        """
        try:
            bucket = flask.current_app.config["DATA_UPLOAD_BUCKET"]
        except KeyError:
            raise InternalError(
                "fence not configured with data upload bucket; can't create signed URL"
            )
        s3_url = "s3://{}/{}".format(bucket, key)
        return S3IndexedFileLocation(s3_url).init_multipart_upload(expires_in)

    @staticmethod
    def complete_multipart_upload(key, uploadId, parts, expires_in=None):
        """
        Complete multipart upload

        Args:
            key(str): object key or `GUID/filename`
            uploadId(str): upload id of the current upload
            parts(list(set)): List of part infos
                [{"Etag": "1234567", "PartNumber": 1}, {"Etag": "4321234", "PartNumber": 2}]

        Returns:
            None if success otherwise an exception
        """
        try:
            bucket = flask.current_app.config["DATA_UPLOAD_BUCKET"]
        except KeyError:
            raise InternalError(
                "fence not configured with data upload bucket; can't create signed URL"
            )
        s3_url = "s3://{}/{}".format(bucket, key)
        S3IndexedFileLocation(s3_url).complete_multipart_upload(
            uploadId, parts, expires_in
        )

    @staticmethod
    def generate_aws_presigned_url_for_part(key, uploadId, partNumber, expires_in):
        """
        Generate presigned url for each part

        Args:
            key(str): object key of `guid/filename`
            uploadID(str): uploadId of the current upload.
            partNumber(int): the part number

        Returns:
            presigned_url(str)
        """
        try:
            bucket = flask.current_app.config["DATA_UPLOAD_BUCKET"]
        except KeyError:
            raise InternalError(
                "fence not configured with data upload bucket; can't create signed URL"
            )
        s3_url = "s3://{}/{}".format(bucket, key)
        return S3IndexedFileLocation(s3_url).generate_presigned_url_for_part_upload(
            uploadId, partNumber, expires_in
        )


class IndexedFile(object):
    """
    A file from the index service that will contain information about access and where
    the physical file lives (could be multiple urls).

    TODO (rudyardrichter, 2018-11-03):
        general clean up of indexd interface; maybe have ABC for this class and blank
        records, and make things as consistent as possible between this and the "blank"
        records (might be tricky since the purpose for the blank record class is to
        create a new record in indexd, rather than look one up; that distinction could
        also be cleaner).

    Args:
        file_id (str): GUID for the file.
    """

    def __init__(self, file_id):
        self.file_id = file_id

    @cached_property
    def indexd_server(self):
        indexd_server = (
            flask.current_app.config.get("INDEXD")
            or flask.current_app.config["BASE_URL"] + "/index"
        )
        return indexd_server.rstrip("/")

    @cached_property
    def index_document(self):
        indexd_server = config.get("INDEXD") or config["BASE_URL"] + "/index"
        url = indexd_server + "/index/"
        try:
            res = requests.get(url + self.file_id)
        except Exception as e:
            logger.error(
                "failed to reach indexd at {0}: {1}".format(url + self.file_id, e)
            )
            raise UnavailableError("Fail to reach id service to find data location")
        if res.status_code == 200:
            try:
                json_response = res.json()
                if "urls" not in json_response:
                    logger.error(
                        "URLs are not included in response from "
                        "indexd: {}".format(url + self.file_id)
                    )
                    raise InternalError("URLs and metadata not found")
                return res.json()
            except Exception as e:
                logger.error(
                    "indexd response missing JSON field {}".format(url + self.file_id)
                )
                raise InternalError("internal error from indexd: {}".format(e))
        elif res.status_code == 404:
            logger.error(
                "Not Found. indexd could not find {}: {}".format(
                    url + self.file_id, res.text
                )
            )
            raise NotFound("No indexed document found with id {}".format(self.file_id))
        else:
            raise UnavailableError(res.text)

    @cached_property
    def indexed_file_locations(self):
        urls = self.index_document.get("urls", [])
        return list(map(IndexedFileLocation.from_url, urls))

    def get_signed_url(
        self,
        protocol,
        action,
        expires_in,
        force_signed_url=True,
        r_pays_project=None,
        file_name=None,
        users_from_passports=None,
        bucket=None,
    ):
        users_from_passports = users_from_passports or {}
        authorized_user = None
        if self.index_document.get("authz"):
            action_to_permission = {
                "upload": "write-storage",
                "download": "read-storage",
            }
            is_authorized, authorized_username = self.get_authorized_with_username(
                action_to_permission[action],
                # keys are usernames
                usernames_from_passports=list(users_from_passports.keys()),
            )
            if not is_authorized:
                msg = (
                    f"Either you weren't authenticated successfully or you don't have "
                    f"{action_to_permission[action]} permission "
                    f"on authorization resource: {self.index_document['authz']}."
                )
                logger.debug(
                    f"denied. authorized_username: {authorized_username}\nmsg:\n{msg}"
                )
                raise Unauthorized(msg)
            authorized_user = users_from_passports.get(authorized_username)
        else:
            if self.public_acl and action == "upload":
                raise Unauthorized(
                    "Cannot upload on public files while using acl field"
                )
            # don't check the authorization if the file is public
            # (downloading public files with no auth is fine)
            if not self.public_acl and not self.check_legacy_authorization(action):
                raise Unauthorized(
                    f"You don't have access permission on this file: {self.file_id}"
                )

        if action is not None and action not in SUPPORTED_ACTIONS:
            raise NotSupported("action {} is not supported".format(action))
        return (
            self._get_signed_url(
                protocol,
                action,
                expires_in,
                force_signed_url,
                r_pays_project,
                file_name,
                authorized_user,
                bucket,
            ),
            authorized_user,
        )

    def _get_signed_url(
        self,
        protocol,
        action,
        expires_in,
        force_signed_url,
        r_pays_project,
        file_name,
        authorized_user=None,
        bucket=None,
    ):
        if action == "upload":
            # NOTE: self.index_document ensures the GUID exists in indexd and raises
            #       an error if not (which is expected to be caught upstream in the
            #       app)
            blank_record = BlankIndex(uploader="", guid=self.index_document.get("did"))
            return blank_record.make_signed_url(
                protocol=protocol,
                file_name=file_name,
                expires_in=expires_in,
                bucket=bucket,
            )

        if not protocol:
            # no protocol specified, return first location as signed url
            try:
                return self.indexed_file_locations[0].get_signed_url(
                    action,
                    expires_in,
                    force_signed_url=force_signed_url,
                    r_pays_project=r_pays_project,
                    authorized_user=authorized_user,
                )
            except IndexError:
                raise NotFound("Can't find any file locations.")

        for file_location in self.indexed_file_locations:
            # allow file location to be https, even if they specific http
            if (file_location.protocol == protocol) or (
                protocol == "http" and file_location.protocol == "https"
            ):
                return file_location.get_signed_url(
                    action,
                    expires_in,
                    force_signed_url=force_signed_url,
                    r_pays_project=r_pays_project,
                    authorized_user=authorized_user,
                )

        raise NotFound(
            "File {} does not have a location with specified "
            "protocol {}.".format(self.file_id, protocol)
        )

    @cached_property
    def set_acls(self):
        if "acl" in self.index_document:
            return set(self.index_document["acl"])
        elif "acls" in self.metadata:
            return set(self.metadata["acls"].split(","))
        else:
            raise Unauthorized("This file is not accessible")

    def get_authorized_with_username(self, action, usernames_from_passports=None):
        """
        Return a tuple of (boolean, str) which represents whether they're authorized
        and their username. username is only returned if `usernames_from_passports`
        is provided and one of the usernames from the passports is authorized.

        Args:
            action (str): Authorization action being performed
            usernames_from_passports (list[str], optional): List of user usernames parsed
                from validated passports

        Returns:
            tuple of (boolean, str): which represents whether they're authorized
        and their username. username is only returned if `usernames_from_passports`
        is provided and one of the usernames from the passports is authorized.
        """
        if not self.index_document.get("authz"):
            raise ValueError("index record missing `authz`")

        logger.debug(
            f"authz check can user {action} on {self.index_document['authz']} for fence? "
            f"if passport provided, IDs parsed: {usernames_from_passports}"
        )

        # handle multiple GA4GH passports as a means of authn/z
        if usernames_from_passports:
            authorized = False
            for username in usernames_from_passports:
                authorized = flask.current_app.arborist.auth_request(
                    jwt=None,
                    user_id=username,
                    service="fence",
                    methods=action,
                    resources=self.index_document["authz"],
                )
                # if any passport provides access, user is authorized
                if authorized:
                    # for google proxy groups and future use: we need to know which
                    # user_id actually gave access
                    return authorized, username
            return authorized, None
        else:
            try:
                token = get_jwt()
            except Unauthorized:
                #  get_jwt raises an Unauthorized error when user is anonymous (no
                #  available token), so to allow anonymous users possible access to
                #  public data, we still make the request to Arborist
                token = None

            return (
                flask.current_app.arborist.auth_request(
                    jwt=token,
                    service="fence",
                    methods=action,
                    resources=self.index_document["authz"],
                ),
                None,
            )

    @cached_property
    def metadata(self):
        return self.index_document.get("metadata", {})

    @cached_property
    def public_acl(self):
        return "*" in self.set_acls

    @login_required({"data"})
    def check_legacy_authorization(self, action):
        # if we have a data file upload without corresponding metadata, the record can
        # have just the `uploader` field and no ACLs. in this just check that the
        # current user's username matches the uploader field
        if self.index_document.get("uploader"):
            username = None
            if flask.g.token:
                username = flask.g.token["context"]["user"]["name"]
            else:
                username = flask.g.user.username
            logger.debug(
                f"authz check using uploader field: {self.index_document.get('uploader')} == {username}"
            )
            return self.index_document.get("uploader") == username

        given_acls = set()
        if hasattr(flask.g, "user"):
            given_acls = set(filter_auth_ids(action, flask.g.user.project_access))
        return len(self.set_acls & given_acls) > 0

    @login_required({"data"})
    def delete_files(self, urls=None, delete_all=True):
        """
        Delete the data files stored at all the locations for this indexed file.

        If a list of URLs is specified, delete only files at those locations;
        otherwise, delete files at all locations.

        Args:
            urls (Optional[List[str]])

        Return:
            Response (str: message, int: status code)
        """
        locations_to_delete = []
        if not urls and delete_all:
            locations_to_delete = self.indexed_file_locations
        else:
            locations_to_delete = list(map(IndexedFileLocation.from_url, urls))
        response = ("No URLs to delete", 200)
        for location in locations_to_delete:
            bucket = location.bucket_name()

            file_suffix = ""
            try:
                file_suffix = location.file_name()
            except Exception as e:
                logger.info(e)
                file_suffix = self.file_id

            logger.info(
                "Attempting to delete file named {} from bucket {}.".format(
                    file_suffix, bucket
                )
            )
            response = location.delete(bucket, file_suffix)

            # check status code not in 200s
            response_status_code = response[1]

            if response_status_code > 399:
                break
        return response

    @login_required({"data"})
    def delete(self):
        rev = self.index_document["rev"]
        path = "{}/index/{}".format(self.indexd_server, self.file_id)
        auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
        params = {"rev": rev}
        response = requests.delete(path, auth=auth, params=params)
        # it's possible that for some reason (something else modified the record in the
        # meantime) that the revision doesn't match, which would lead to error here
        if response.status_code != 200:
            return (flask.jsonify(response.json()), 500)
        return ("", 204)


class IndexedFileLocation(object):
    """
    Parent class for indexed file locations.

    This will catch all non-aws/gs cases for now. If custom functionality is
    needed for a new file location, create a new subclass.
    """

    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.protocol = IndexedFileLocation._get_protocol(url)

    @staticmethod
    def _get_protocol(url):
        # Assume that urls are have internal storage protocol included
        # e.g. az://storageaccount.blob.core.windows.net/containername/some/path/to/file.txt
        # or s3://my-s3-url, gs://my-gs-url, https://my-https-url
        parsed_url = urlparse(url)

        return parsed_url.scheme

    @staticmethod
    def from_url(url):
        protocol = IndexedFileLocation._get_protocol(url)
        if (protocol is not None) and (protocol not in SUPPORTED_PROTOCOLS):
            raise NotSupported(
                "The specified protocol {} is not supported".format(protocol)
            )
        if protocol == "s3":
            return S3IndexedFileLocation(url)
        elif protocol == "gs":
            return GoogleStorageIndexedFileLocation(url)
        elif protocol == "az":
            return AzureBlobStorageIndexedFileLocation(url)
        return IndexedFileLocation(url)

    def get_signed_url(
        self,
        action,
        expires_in,
        force_signed_url=True,
        users_from_passports=None,
        **kwargs,
    ):
        return self.url


class S3IndexedFileLocation(IndexedFileLocation):
    """
    An indexed file that lives in an AWS S3 bucket.

    _assume_role_cache is used as an in mem cache for holding role credentials
    """

    # expected structure { role_arn: (rv, expires_at) }
    _assume_role_cache = {}

    @classmethod
    def assume_role(cls, bucket_cred, expires_in, aws_creds_config, boto=None):
        """
        Args:
            bucket_cred
            expires_in
            aws_creds_config
            boto (optional): provide `boto` when calling this function
                outside of application context, to avoid errors when
                using `flask.current_app`.
        """
        role_arn = get_value(
            bucket_cred, "role-arn", InternalError("role-arn of that bucket is missing")
        )
        expiry = time.time() + expires_in

        # try to retrieve from local in-memory cache
        rv, expires_at = cls._assume_role_cache.get(role_arn, (None, 0))
        if expires_at > expiry:
            return rv

        # try to retrieve from database cache
        if hasattr(flask.current_app, "db"):  # we don't have db in startup
            with flask.current_app.db.session as session:
                cache = (
                    session.query(AssumeRoleCacheAWS)
                    .filter(AssumeRoleCacheAWS.arn == role_arn)
                    .first()
                )
                if cache and cache.expires_at and cache.expires_at > expiry:
                    rv = dict(
                        aws_access_key_id=cache.aws_access_key_id,
                        aws_secret_access_key=cache.aws_secret_access_key,
                        aws_session_token=cache.aws_session_token,
                    )
                    cls._assume_role_cache[role_arn] = rv, cache.expires_at
                    return rv

        # retrieve from AWS, with additional ASSUME_ROLE_CACHE_SECONDS buffer for cache
        boto = boto or flask.current_app.boto

        # checking fence config if aws session can be longer than one hour
        role_cache_increase = 0
        if config["MAX_ROLE_SESSION_INCREASE"]:
            role_cache_increase = int(config["ASSUME_ROLE_CACHE_SECONDS"])

        assumed_role = boto.assume_role(
            role_arn,
            expires_in + role_cache_increase,
            aws_creds_config,
        )

        cred = get_value(
            assumed_role, "Credentials", InternalError("fail to assume role")
        )
        rv = {
            "aws_access_key_id": get_value(
                cred,
                "AccessKeyId",
                InternalError("outdated format. AccessKeyId missing"),
            ),
            "aws_secret_access_key": get_value(
                cred,
                "SecretAccessKey",
                InternalError("outdated format. SecretAccessKey missing"),
            ),
            "aws_session_token": get_value(
                cred,
                "SessionToken",
                InternalError("outdated format. Session token missing"),
            ),
        }
        expires_at = get_value(
            cred, "Expiration", InternalError("outdated format. Expiration missing")
        ).timestamp()

        # stores back to cache
        cls._assume_role_cache[role_arn] = rv, expires_at
        if hasattr(flask.current_app, "db"):  # we don't have db in startup
            with flask.current_app.db.session as session:
                session.execute(
                    """\
                    INSERT INTO assume_role_cache (
                        arn,
                        expires_at,
                        aws_access_key_id,
                        aws_secret_access_key,
                        aws_session_token
                    ) VALUES (
                        :arn,
                        :expires_at,
                        :aws_access_key_id,
                        :aws_secret_access_key,
                        :aws_session_token
                    ) ON CONFLICT (arn) DO UPDATE SET
                        expires_at = EXCLUDED.expires_at,
                        aws_access_key_id = EXCLUDED.aws_access_key_id,
                        aws_secret_access_key = EXCLUDED.aws_secret_access_key,
                        aws_session_token = EXCLUDED.aws_session_token;""",
                    dict(arn=role_arn, expires_at=expires_at, **rv),
                )
        return rv

    def bucket_name(self):
        """
        Return:
            Optional[str]: bucket name or None if not in config
        """
        s3_buckets = get_value(
            flask.current_app.config,
            "S3_BUCKETS",
            InternalError("S3_BUCKETS not configured"),
        )
        for bucket in s3_buckets:
            if re.match("^" + bucket + "$", self.parsed_url.netloc):
                return bucket
        return None

    def file_name(self):
        file_name = self.parsed_url.path[1:]
        return file_name

    @classmethod
    def get_credential_to_access_bucket(
        cls, bucket_name, aws_creds, expires_in, boto=None
    ):
        s3_buckets = get_value(
            config, "S3_BUCKETS", InternalError("S3_BUCKETS not configured")
        )
        if len(aws_creds) == 0 and len(s3_buckets) == 0:
            raise InternalError("no bucket is configured")
        if len(aws_creds) == 0 and len(s3_buckets) > 0:
            raise InternalError("credential for buckets is not configured")

        bucket_cred = s3_buckets.get(bucket_name)
        if bucket_cred is None:
            logger.debug(f"Bucket '{bucket_name}' not found in S3_BUCKETS config")
            raise InternalError("permission denied for bucket")

        cred_key = get_value(
            bucket_cred, "cred", InternalError("credential of that bucket is missing")
        )

        # this is a special case to support public buckets where we do *not* want to
        # try signing at all
        if cred_key == "*":
            return {"aws_access_key_id": "*"}

        if "role-arn" not in bucket_cred:
            return get_value(
                aws_creds,
                cred_key,
                InternalError("aws credential of that bucket is not found"),
            )
        else:
            aws_creds_config = get_value(
                aws_creds,
                cred_key,
                InternalError("aws credential of that bucket is not found"),
            )
            return S3IndexedFileLocation.assume_role(
                bucket_cred, expires_in, aws_creds_config, boto
            )

    def get_bucket_region(self):
        s3_buckets = get_value(
            config, "S3_BUCKETS", InternalError("S3_BUCKETS not configured")
        )
        if len(s3_buckets) == 0:
            return None

        bucket_cred = s3_buckets.get(self.bucket_name())
        if bucket_cred is None:
            return None

        if "region" not in bucket_cred:
            return None
        else:
            return bucket_cred["region"]

    def get_signed_url(
        self,
        action,
        expires_in,
        force_signed_url=True,
        authorized_user=None,
        **kwargs,
    ):

        aws_creds = get_value(
            config, "AWS_CREDENTIALS", InternalError("credentials not configured")
        )
        s3_buckets = get_value(
            config, "S3_BUCKETS", InternalError("S3_BUCKETS not configured")
        )

        bucket_name = self.bucket_name()
        bucket = s3_buckets.get(bucket_name)

        if bucket and bucket.get("endpoint_url"):
            http_url = bucket["endpoint_url"].strip("/") + "/{}/{}".format(
                self.parsed_url.netloc, self.parsed_url.path.strip("/")
            )
        else:
            http_url = "https://{}.s3.amazonaws.com/{}".format(
                self.parsed_url.netloc, self.parsed_url.path.strip("/")
            )

        credential = S3IndexedFileLocation.get_credential_to_access_bucket(
            bucket_name, aws_creds, expires_in
        )

        # if we don't need to force the signed url, just return the raw
        # s3 url
        aws_access_key_id = get_value(
            credential,
            "aws_access_key_id",
            InternalError("aws configuration not found"),
        )
        # `aws_access_key_id == "*"` is a special case to support public buckets
        # where we do *not* want to try signing at all. the other case is that the
        # data is public and user requested to not sign the url
        if aws_access_key_id == "*" or (not force_signed_url):
            return http_url

        region = self.get_bucket_region()
        if not region and not bucket.get("endpoint_url"):
            region = flask.current_app.boto.get_bucket_region(
                self.parsed_url.netloc, credential
            )

        auth_info = _get_auth_info_for_id_or_from_request(user=authorized_user)

        url = generate_aws_presigned_url(
            http_url,
            ACTION_DICT["s3"][action],
            credential,
            "s3",
            region,
            expires_in,
            auth_info,
        )

        return url

    def init_multipart_upload(self, expires_in):
        """
        Initialize multipart upload

        Args:
            expires(int): expiration time

        Returns:
            UploadId(str)
        """
        aws_creds = get_value(
            config, "AWS_CREDENTIALS", InternalError("credentials not configured")
        )
        credentials = S3IndexedFileLocation.get_credential_to_access_bucket(
            self.bucket_name(), aws_creds, expires_in
        )

        return multipart_upload.initilize_multipart_upload(
            self.parsed_url.netloc, self.parsed_url.path.strip("/"), credentials
        )

    def generate_presigned_url_for_part_upload(self, uploadId, partNumber, expires_in):
        """
        Generate presigned url for uploading object part given uploadId and part number

        Args:
            uploadId(str): uploadID of the multipart upload
            partNumber(int): part number
            expires(int): expiration time

        Returns:
            presigned_url(str)
        """
        aws_creds = get_value(
            config, "AWS_CREDENTIALS", InternalError("credentials not configured")
        )
        credential = S3IndexedFileLocation.get_credential_to_access_bucket(
            self.bucket_name(), aws_creds, expires_in
        )

        region = self.get_bucket_region()
        if not region:
            region = flask.current_app.boto.get_bucket_region(
                self.parsed_url.netloc, credential
            )

        return multipart_upload.generate_presigned_url_for_uploading_part(
            self.parsed_url.netloc,
            self.parsed_url.path.strip("/"),
            credential,
            uploadId,
            partNumber,
            region,
            expires_in,
        )

    def complete_multipart_upload(self, uploadId, parts, expires_in):
        """
        Complete multipart upload.

        Args:
            uploadId(str): upload id of the current upload
            parts(list(set)): List of part infos
                    [{"Etag": "1234567", "PartNumber": 1}, {"Etag": "4321234", "PartNumber": 2}]
        """
        aws_creds = get_value(
            config, "AWS_CREDENTIALS", InternalError("credentials not configured")
        )

        credentials = S3IndexedFileLocation.get_credential_to_access_bucket(
            self.bucket_name(), aws_creds, expires_in
        )

        multipart_upload.complete_multipart_upload(
            self.parsed_url.netloc,
            self.parsed_url.path.strip("/"),
            credentials,
            uploadId,
            parts,
        )

    def delete(self, bucket, file_id):
        try:
            return flask.current_app.boto.delete_data_file(bucket, file_id)
        except Exception as e:
            logger.error(e)
            return ("Failed to delete data file.", 500)


class GoogleStorageIndexedFileLocation(IndexedFileLocation):
    """
    An indexed file that lives in a Google Storage bucket.

    _assume_role_cache_gs is used for in mem caching of GCP role credentials
    """

    # expected structore { proxy_group_id: (private_key, expires_at) }
    _assume_role_cache_gs = {}

    def get_resource_path(self):
        return self.parsed_url.netloc.strip("/") + "/" + self.parsed_url.path.strip("/")

    def get_signed_url(
        self,
        action,
        expires_in,
        force_signed_url=True,
        r_pays_project=None,
        authorized_user=None,
    ):
        resource_path = self.get_resource_path()

        auth_info = _get_auth_info_for_id_or_from_request(user=authorized_user)

        if not force_signed_url:
            url = "https://storage.cloud.google.com/" + resource_path
        elif _is_anonymous_user(auth_info):
            url = self._generate_anonymous_google_storage_signed_url(
                ACTION_DICT["gs"][action], resource_path, int(expires_in)
            )
        else:
            url = self._generate_google_storage_signed_url(
                ACTION_DICT["gs"][action],
                resource_path,
                int(expires_in),
                auth_info.get("user_id"),
                auth_info.get("username"),
                r_pays_project=r_pays_project,
            )

        return url

    def _generate_anonymous_google_storage_signed_url(
        self, http_verb, resource_path, expires_in, r_pays_project=None
    ):
        # we will use the main fence SA service account to sign anonymous requests
        private_key = get_google_app_creds()
        final_url = cirrus.google_cloud.utils.get_signed_url(
            resource_path,
            http_verb,
            expires_in,
            extension_headers=None,
            service_account_creds=private_key,
            requester_pays_user_project=r_pays_project,
        )
        return final_url

    def bucket_name(self):
        resource_path = self.get_resource_path()

        bucket_name = None
        try:
            bucket_name = resource_path.split("/")[0]
        except Exception as exc:
            logger.error("Unable to get bucket name from resource path. {}".format(exc))

        return bucket_name

    def file_name(self):
        resource_path = self.get_resource_path()

        file_name = None
        try:
            file_name = "/".join(resource_path.split("/")[1:])
        except Exception as exc:
            logger.error("Unable to get file name from resource path. {}".format(exc))

        return file_name

    def _generate_google_storage_signed_url(
        self,
        http_verb,
        resource_path,
        expires_in,
        user_id,
        username,
        r_pays_project=None,
    ):
        proxy_group_id = get_or_create_proxy_group_id(
            user_id=user_id, username=username
        )
        expiration_time = int(time.time()) + expires_in
        is_cached = False

        if proxy_group_id in self._assume_role_cache_gs:
            (
                raw_private_key,
                expires_at,
            ) = self._assume_role_cache_gs.get(proxy_group_id, (None, None))

            if expires_at and expires_at > expiration_time:
                is_cached = True
                private_key = raw_private_key
                expires_at = expires_at
            else:
                del self._assume_role_cache_gs[proxy_group_id]

        if not is_cached and hasattr(flask.current_app, "db"):
            with flask.current_app.db.session as session:
                cache = (
                    session.query(AssumeRoleCacheGCP)
                    .filter(AssumeRoleCacheGCP.gcp_proxy_group_id == proxy_group_id)
                    .first()
                )
                if cache and cache.expires_at > expiration_time:
                    private_key = json.loads(cache.gcp_private_key)
                    expires_at = cache.expires_at
                    self._assume_role_cache_gs[proxy_group_id] = (
                        private_key,
                        expires_at,
                    )
                    is_cached = True

        # check again to see if we got cached creds from the database,
        # if not we need to actually get the creds and then cache them
        if not is_cached:
            private_key, key_db_entry = get_or_create_primary_service_account_key(
                user_id=user_id, username=username, proxy_group_id=proxy_group_id
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
            if key_db_entry.expires < expiration_time:
                private_key = create_primary_service_account_key(
                    user_id=user_id, username=username, proxy_group_id=proxy_group_id
                )
            self._assume_role_cache_gs[proxy_group_id] = (
                private_key,
                key_db_entry.expires,
            )

            db_entry = {}
            db_entry["gcp_proxy_group_id"] = proxy_group_id
            db_entry["gcp_private_key"] = json.dumps(private_key)
            db_entry["expires_at"] = key_db_entry.expires

            if hasattr(flask.current_app, "db"):  # we don't have db in startup
                with flask.current_app.db.session as session:
                    # we don't need to populate gcp_key_db_entry anymore, it was for
                    # expiration, but now we have a specific field for that.
                    session.execute(
                        """\
                        INSERT INTO gcp_assume_role_cache (
                            expires_at,
                            gcp_proxy_group_id,
                            gcp_private_key,
                            gcp_key_db_entry
                        ) VALUES (
                            :expires_at,
                            :gcp_proxy_group_id,
                            :gcp_private_key,
                            NULL
                        ) ON CONFLICT (gcp_proxy_group_id) DO UPDATE SET
                            expires_at = EXCLUDED.expires_at,
                            gcp_proxy_group_id = EXCLUDED.gcp_proxy_group_id,
                            gcp_private_key = EXCLUDED.gcp_private_key,
                            gcp_key_db_entry = EXCLUDED.gcp_key_db_entry;""",
                        db_entry,
                    )

            if config["ENABLE_AUTOMATIC_BILLING_PERMISSION_SIGNED_URLS"]:
                give_service_account_billing_access_if_necessary(
                    private_key,
                    r_pays_project,
                    default_billing_project=config["BILLING_PROJECT_FOR_SIGNED_URLS"],
                )

        # use configured project if it exists and no user project was given
        if config["BILLING_PROJECT_FOR_SIGNED_URLS"] and not r_pays_project:
            r_pays_project = config["BILLING_PROJECT_FOR_SIGNED_URLS"]

        final_url = cirrus.google_cloud.utils.get_signed_url(
            resource_path,
            http_verb,
            expires_in,
            extension_headers=None,
            service_account_creds=private_key,
            requester_pays_user_project=r_pays_project,
        )
        return final_url

    def delete(self, bucket, file_id):
        try:
            with GoogleCloudManager(
                creds=config["CIRRUS_CFG"]["GOOGLE_STORAGE_CREDS"]
            ) as gcm:
                gcm.delete_data_file(bucket, file_id)
            return ("", 204)
        except Exception as e:
            logger.error(e)
            try:
                status_code = e.resp.status
            except Exception as exc:
                logger.error(exc)
                status_code = 500
            return ("Failed to delete data file.", status_code)


class AzureBlobStorageIndexedFileLocation(IndexedFileLocation):
    """
    An indexed file that lives in an Azure Blob Storage container.
    """

    def _generate_azure_blob_storage_sas(
        self,
        container_name,
        blob_name,
        expires_in,
        azure_creds,
        permission,
    ):
        """
        Generate an Azure Blob Storage SAS URL

        :param str container_name:
            Name of container.
        :param str blob_name:
            Name of blob.
        :param int expires_in:
            The SAS token will expire in a given number of seconds from datetime.utcnow()
        :param str azure_creds:
            The Azure Blob Storage Account connection string
        :param AccountSasPermissions permission:
            The permissions associated with the shared access signature.
        """
        blob_service_client = BlobServiceClient.from_connection_string(azure_creds)

        converted_url = self._get_converted_url()

        # if the storage account used with the blob service client doesn't match the storage account
        # used with self.url (az://<storageaccount>.blob.core.windows.net/<somecontainer>/some/path/to/file.txt)
        # then return the converted url instead (https://<storageaccount>.blob.core.windows.net/<somecontainer>/some/path/to/file.txt)
        # this will prevent adding a SAS token using the wrong storage account for the signed URL
        if self._check_storage_account_name_matches(blob_service_client) is False:
            return converted_url

        sas_query = generate_blob_sas(
            blob_service_client.account_name,
            container_name,
            blob_name,
            account_key=blob_service_client.credential.account_key,
            resource_types=ResourceTypes(object=True),
            permission=permission,
            expiry=datetime.utcnow() + timedelta(seconds=expires_in),
        )

        sas_url = converted_url + "?" + sas_query
        return sas_url

    def _check_storage_account_name_matches(self, blob_service_client):
        # assumes that the url form is az://<storageaccount>.blob.core.windows.net/<somecontainer>/some/path/to/file.txt
        return self.parsed_url.netloc == blob_service_client.primary_hostname

    def _get_container_and_blob(self):
        container_and_blob_parts = self.parsed_url.path.strip("/").split("/")
        container_name = container_and_blob_parts[0]
        blob_name = "/".join(container_and_blob_parts[1:])

        return container_name, blob_name

    def bucket_name(self):
        """
        Get the bucket name.
        In this case it's the Azure Storage Blob Container name.
        """
        container_name, _ = self._get_container_and_blob()

        return container_name

    def file_name(self):
        """
        Get the blob name as a file name
        Similar to getting a file_name for the other IndexedFileLocation(s)
        """
        _, blob_name = self._get_container_and_blob()

        return blob_name

    def _get_converted_url(self):
        """
        Convert url from internal representation
        of az://<storageaccountname>.blob.core.windows.net/<containername>/some/path/to/file.txt
        to https://<storageaccountname>.blob.core.windows.net/<containername>/some/path/to/file.txt
        """
        new_parsed_url = ParseResult(
            scheme="https",
            netloc=self.parsed_url.netloc,
            path=self.parsed_url.path,
            params=self.parsed_url.params,
            query=self.parsed_url.query,
            fragment=self.parsed_url.fragment,
        )

        return urlunparse(new_parsed_url)

    def get_signed_url(
        self,
        action,
        expires_in,
        force_signed_url=True,
        authorized_user=None,
        **kwargs,
    ):
        """
        Get a signed url for a given action

        This call will check for AZ_BLOB_CREDENTIALS which should be
        included in the fence configuration.

        Set AZ_BLOB_CREDENTIALS to a valid Azure Blob Storage Account
        connection string.

        Set AZ_BLOB_CREDENTIALS to '*' if you have a public Azure Storage
        account associated with the indexed file. In this case,
        you should expect an unsigned URL for the file that's been indexed.

        :param str action:
            Get a signed url for an action like "upload" or "download".
        :param int expires_in:
            The SAS token will expire in a given number of seconds from datetime.utcnow()
        :param bool force_signed_url:
            Enforce signing the URL for the Azure Blob Storage Account using a SAS token.
            The default is True.
        """
        azure_creds = get_value(
            config,
            "AZ_BLOB_CREDENTIALS",
            InternalError("Azure Blob credentials not configured"),
        )

        container_name, blob_name = self._get_container_and_blob()

        auth_info = _get_auth_info_for_id_or_from_request(user=authorized_user)
        if _is_anonymous_user(auth_info):
            logger.info(f"Attempting to get a signed url for an anonymous user")

        # if it's public and we don't need to force the signed url, just return the raw
        # url
        # `azure_creds == "*"` is a special case to support public buckets
        # where we do *not* want to try signing at all. the other case is that the
        # data is public and user requested to not sign the url
        if azure_creds == "*" or (not force_signed_url):
            return self._get_converted_url()

        url = self._generate_azure_blob_storage_sas(
            container_name,
            blob_name,
            expires_in,
            azure_creds,
            permission=AccountSasPermissions(read=True)
            if action == "download"
            else AccountSasPermissions(read=True, write=True),
        )

        return url

    def delete(self, container, blob):  # pylint: disable=R0201
        """
        Delete the container/blob, implementation for IndexedFileLocation.delete()

        This call will check for AZ_BLOB_CREDENTIALS which should be
        included in the fence configuration.

        Set AZ_BLOB_CREDENTIALS to a valid Azure Blob Storage Account
        connection string.

        :param str container:
            Name of container.
        :param str blob:
            Name of blob.
        """
        try:
            azure_creds = get_value(
                config,
                "AZ_BLOB_CREDENTIALS",
                InternalError("Azure Blob credentials not configured"),
            )

            blob_service_client = BlobServiceClient.from_connection_string(azure_creds)
            blob_client = blob_service_client.get_blob_client(container, blob)
            blob_client.delete_blob()

            return (flask.jsonify({"message": f"deleted {blob} from {container}"}), 204)
        except Exception as e:
            logger.error(e)
            try:
                status_code = e.resp.status
            except Exception as exc:
                logger.error(exc)
                status_code = 500
            return ("Failed to delete data file.", status_code)


def _get_auth_info_for_id_or_from_request(
    sub_type=str, user=None, username=None, db_session=None
):
    """
    Attempt to parse the request to get information about user and client.
    Fallback to populated information about an anonymous user.

    By default, cast `sub` to str. Use `sub_type` to override this behavior.

    WARNING: This does NOT actually check authorization information and always falls
             back on anonymous user information. DO NOT USE THIS AS A MEANS TO AUTHORIZE,
             IT WILL ALWAYS GIVE YOU BACK ANONYMOUS USER INFO. Only use this
             after you've authorized the access to the data via other means.
    """
    db_session = db_session or current_session

    # set default "anonymous" user_id and username
    # this is fine b/c it might be public data or a client token that is not
    # linked to a user
    final_user_id = None
    if sub_type == str:
        final_user_id = sub_type(ANONYMOUS_USER_ID)
    final_username = ANONYMOUS_USERNAME

    token = ""
    try:
        if user:
            final_username = user.username
            final_user_id = sub_type(user.id)
        elif username:
            result = query_for_user(db_session, username)
            final_username = result.username
            final_user_id = sub_type(result.id)
        else:
            token = validate_request(scope={"user"}, audience=config.get("BASE_URL"))
            set_current_token(token)
            final_user_id = current_token["sub"]
            final_user_id = sub_type(final_user_id)
            final_username = current_token["context"]["user"]["name"]
    except Exception as exc:
        logger.info(
            f"could not determine user auth info from request. setting anonymous user information. Details:\n{exc}"
        )

    client_id = ""
    try:
        if not token:
            token = validate_request(scope=[], audience=config.get("BASE_URL"))
        set_current_token(token)
        client_id = current_token.get("azp") or ""
    except Exception as exc:
        logger.info(
            f"could not determine client auth info from request. setting anonymous client information. Details:\n{exc}"
        )

    if final_username == ANONYMOUS_USERNAME and client_id != "":
        raise Forbidden("This endpoint does not support client credentials tokens")

    return {
        "user_id": final_user_id,
        "username": final_username,
        "client_id": client_id,
    }


def _is_anonymous_user(auth_info):
    """
    Check if there's a current user authenticated or if request is anonymous
    """
    auth_info = auth_info or _get_auth_info_for_id_or_from_request()
    return str(auth_info.get("user_id")) == ANONYMOUS_USER_ID


def filter_auth_ids(action, list_auth_ids):
    checked_permission = ""
    if action == "download":
        checked_permission = "read-storage"
    elif action == "upload":
        checked_permission = "write-storage"
    authorized_dbgaps = []
    for key, values in list(list_auth_ids.items()):
        if checked_permission in values:
            authorized_dbgaps.append(key)
    return authorized_dbgaps
