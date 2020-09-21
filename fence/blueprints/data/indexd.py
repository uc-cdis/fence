import re
import time
from urllib.parse import urlparse

from cached_property import cached_property
import cirrus
from cirrus import GoogleCloudManager
from cdislogging import get_logger
from cdispyutils.config import get_value
from cdispyutils.hmac4 import generate_aws_presigned_url
import flask
import requests

from fence.auth import (
    get_jwt,
    has_oauth,
    current_token,
    login_required,
    set_current_token,
    validate_request,
    JWTError,
)
from fence.config import config
from fence.errors import (
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
from fence.utils import get_valid_expiration_from_request
from . import multipart_upload


logger = get_logger(__name__)

ACTION_DICT = {
    "s3": {"upload": "PUT", "download": "GET"},
    "gs": {"upload": "PUT", "download": "GET"},
}

SUPPORTED_PROTOCOLS = ["s3", "http", "ftp", "https", "gs"]
SUPPORTED_ACTIONS = ["upload", "download"]
ANONYMOUS_USER_ID = "anonymous"
ANONYMOUS_USERNAME = "anonymous"


def get_signed_url_for_file(action, file_id, file_name=None):
    requested_protocol = flask.request.args.get("protocol", None)
    r_pays_project = flask.request.args.get("userProject", None)

    # default to signing the url even if it's a public object
    # this will work so long as we're provided a user token
    force_signed_url = True
    if flask.request.args.get("no_force_sign"):
        force_signed_url = False

    indexed_file = IndexedFile(file_id)
    expires_in = config.get("MAX_PRESIGNED_URL_TTL", 3600)
    requested_expires_in = get_valid_expiration_from_request()
    if requested_expires_in:
        expires_in = min(requested_expires_in, expires_in)

    signed_url = indexed_file.get_signed_url(
        requested_protocol,
        action,
        expires_in,
        force_signed_url=force_signed_url,
        r_pays_project=r_pays_project,
        file_name=file_name,
    )
    return {"url": signed_url}


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

    def make_signed_url(self, file_name, expires_in=None):
        """
        Works for upload only; S3 only (only supported case for data upload flow
        currently).

        Args:
            file_name (str)
            expires_in (int)

        Return:
            S3IndexedFileLocation
        """
        try:
            bucket = flask.current_app.config["DATA_UPLOAD_BUCKET"]
        except KeyError:
            raise InternalError(
                "fence not configured with data upload bucket; can't create signed URL"
            )
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
        return S3IndexedFileLocation(s3_url).generate_presigne_url_for_part_upload(
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
    ):
        if self.public and action == "upload":
            raise Unauthorized("Cannot upload on public files")
        # don't check the authorization if the file is public
        # (downloading public files with no auth is fine)
        if not self.public and not self.check_authorization(action):
            raise Unauthorized(
                "You don't have access permission on this file: {}".format(self.file_id)
            )
        if action is not None and action not in SUPPORTED_ACTIONS:
            raise NotSupported("action {} is not supported".format(action))
        return self._get_signed_url(
            protocol, action, expires_in, force_signed_url, r_pays_project, file_name
        )

    def _get_signed_url(
        self, protocol, action, expires_in, force_signed_url, r_pays_project, file_name
    ):
        if action == "upload":
            # NOTE: self.index_document ensures the GUID exists in indexd and raises
            #       an error if not (which is expected to be caught upstream in the
            #       app)
            blank_record = BlankIndex(uploader="", guid=self.index_document.get("did"))
            return blank_record.make_signed_url(
                file_name=file_name, expires_in=expires_in
            )

        if not protocol:
            # no protocol specified, return first location as signed url
            try:
                return self.indexed_file_locations[0].get_signed_url(
                    action,
                    expires_in,
                    public_data=self.public,
                    force_signed_url=force_signed_url,
                    r_pays_project=r_pays_project,
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
                    public_data=self.public,
                    force_signed_url=force_signed_url,
                    r_pays_project=r_pays_project,
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

    def check_authz(self, action):
        if not self.index_document.get("authz"):
            raise ValueError("index record missing `authz`")

        logger.debug(
            f"authz check can user {action} on {self.index_document['authz']} for fence?"
        )
        return flask.current_app.arborist.auth_request(
            jwt=get_jwt(),
            service="fence",
            methods=action,
            resources=self.index_document["authz"],
        )

    @cached_property
    def metadata(self):
        return self.index_document.get("metadata", {})

    @cached_property
    def public(self):
        authz_resources = list(self.set_acls)
        authz_resources.extend(self.index_document.get("authz", []))
        return "*" in authz_resources or "/open" in authz_resources

    @login_required({"data"})
    def check_authorization(self, action):
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

        try:
            action_to_method = {"upload": "write-storage", "download": "read-storage"}
            method = action_to_method[action]
            # action should be upload or download
            # return bool for authorization
            return self.check_authz(method)
        except ValueError:
            # this is ok; we'll default to ACL field (previous behavior)
            # may want to deprecate in future
            logger.info(
                "Couldn't find `authz` field on indexd record, falling back to `acl`."
            )

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
            None
        """
        locations_to_delete = []
        if urls is None and delete_all:
            locations_to_delete = self.indexed_file_locations
        else:
            locations_to_delete = [
                location for location in locations_to_delete if location.url in urls
            ]
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
            return location.delete(bucket, file_suffix)

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
        self.protocol = self.parsed_url.scheme

    @staticmethod
    def from_url(url):
        protocol = urlparse(url).scheme
        if (protocol is not None) and (protocol not in SUPPORTED_PROTOCOLS):
            raise NotSupported(
                "The specified protocol {} is not supported".format(protocol)
            )
        if protocol == "s3":
            return S3IndexedFileLocation(url)
        elif protocol == "gs":
            return GoogleStorageIndexedFileLocation(url)
        return IndexedFileLocation(url)

    def get_signed_url(
        self, action, expires_in, public_data=False, force_signed_url=True, **kwargs
    ):
        return self.url


class S3IndexedFileLocation(IndexedFileLocation):
    """
    An indexed file that lives in an AWS S3 bucket.
    """

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
        boto = boto or flask.current_app.boto

        role_arn = get_value(
            bucket_cred, "role-arn", InternalError("role-arn of that bucket is missing")
        )
        assumed_role = boto.assume_role(role_arn, expires_in, aws_creds_config)
        cred = get_value(
            assumed_role, "Credentials", InternalError("fail to assume role")
        )
        return {
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
                InternalError("outdated format. Sesssion token missing"),
            ),
        }

    def bucket_name(self):
        """
        Return:
            Optional[str]: bucket name or None if not not in cofig
        """
        s3_buckets = get_value(
            flask.current_app.config,
            "S3_BUCKETS",
            InternalError("buckets not configured"),
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
            config, "S3_BUCKETS", InternalError("buckets not configured")
        )
        if len(aws_creds) == 0 and len(s3_buckets) == 0:
            raise InternalError("no bucket is configured")
        if len(aws_creds) == 0 and len(s3_buckets) > 0:
            raise InternalError("credential for buckets is not configured")

        bucket_cred = s3_buckets.get(bucket_name)
        if bucket_cred is None:
            raise Unauthorized("permission denied for bucket")

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
            config, "S3_BUCKETS", InternalError("buckets not configured")
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
        self, action, expires_in, public_data=False, force_signed_url=True, **kwargs
    ):
        aws_creds = get_value(
            config, "AWS_CREDENTIALS", InternalError("credentials not configured")
        )
        s3_buckets = get_value(
            config, "S3_BUCKETS", InternalError("buckets not configured")
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

        # if it's public and we don't need to force the signed url, just return the raw
        # s3 url
        aws_access_key_id = get_value(
            credential,
            "aws_access_key_id",
            InternalError("aws configuration not found"),
        )
        # `aws_access_key_id == "*"` is a special case to support public buckets
        # where we do *not* want to try signing at all. the other case is that the
        # data is public and user requested to not sign the url
        if aws_access_key_id == "*" or (public_data and not force_signed_url):
            return http_url

        region = self.get_bucket_region()
        if not region and not bucket.get("endpoint_url"):
            region = flask.current_app.boto.get_bucket_region(
                self.parsed_url.netloc, credential
            )

        user_info = _get_user_info()

        url = generate_aws_presigned_url(
            http_url,
            ACTION_DICT["s3"][action],
            credential,
            "s3",
            region,
            expires_in,
            user_info,
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

    def generate_presigne_url_for_part_upload(self, uploadId, partNumber, expires_in):
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
    """

    def get_resource_path(self):
        return self.parsed_url.netloc.strip("/") + "/" + self.parsed_url.path.strip("/")

    def get_signed_url(
        self,
        action,
        expires_in,
        public_data=False,
        force_signed_url=True,
        r_pays_project=None,
    ):
        resource_path = self.get_resource_path()

        user_info = _get_user_info()

        if public_data and not force_signed_url:
            url = "https://storage.cloud.google.com/" + resource_path
        elif public_data and _is_anonymous_user(user_info):
            expiration_time = int(time.time()) + int(expires_in)
            url = self._generate_anonymous_google_storage_signed_url(
                ACTION_DICT["gs"][action], resource_path, expiration_time
            )
        else:
            expiration_time = int(time.time()) + int(expires_in)
            url = self._generate_google_storage_signed_url(
                ACTION_DICT["gs"][action],
                resource_path,
                expiration_time,
                user_info.get("user_id"),
                user_info.get("username"),
                r_pays_project=r_pays_project,
            )

        return url

    def _generate_anonymous_google_storage_signed_url(
        self, http_verb, resource_path, expiration_time, r_pays_project=None
    ):
        # we will use the main fence SA service account to sign anonymous requests
        private_key = get_google_app_creds()
        final_url = cirrus.google_cloud.utils.get_signed_url(
            resource_path,
            http_verb,
            expiration_time,
            extension_headers=None,
            content_type="",
            md5_value="",
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
        expiration_time,
        user_id,
        username,
        r_pays_project=None,
    ):
        proxy_group_id = get_or_create_proxy_group_id()

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
        if key_db_entry and key_db_entry.expires < expiration_time:
            private_key = create_primary_service_account_key(
                user_id=user_id, username=username, proxy_group_id=proxy_group_id
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
            expiration_time,
            extension_headers=None,
            content_type="",
            md5_value="",
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


def _get_user_info():
    """
    Attempt to parse the request for token to authenticate the user. fallback to
    populated information about an anonymous user.
    """
    try:
        set_current_token(validate_request(aud={"user"}))
        user_id = str(current_token["sub"])
        username = current_token["context"]["user"]["name"]
    except JWTError:
        # this is fine b/c it might be public data, sign with anonymous username/id
        user_id = ANONYMOUS_USER_ID
        username = ANONYMOUS_USERNAME

    return {"user_id": user_id, "username": username}


def _is_anonymous_user(user_info):
    """
    Check if there's a current user authenticated or if request is anonymous
    """
    user_info = user_info or _get_user_info()
    return user_info.get("user_id") == ANONYMOUS_USER_ID


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
