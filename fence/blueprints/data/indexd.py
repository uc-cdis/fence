import re
import time
from urlparse import urlparse
import uuid

from authutils.token import current_token
from cached_property import cached_property
import cirrus
from cdispyutils.config import get_value
from cdispyutils.hmac4 import generate_aws_presigned_url
import flask
import requests

from fence.auth import (
    current_token,
    login_required,
    set_current_token,
    validate_request,
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
)


from fence.config import config

ACTION_DICT = {
    "s3": {"upload": "PUT", "download": "GET"},
    "gs": {"upload": "PUT", "download": "GET"},
}

SUPPORTED_PROTOCOLS = ["s3", "http", "ftp", "https", "gs"]
SUPPORTED_ACTIONS = ["upload", "download"]


def get_signed_url_for_file(action, file_id):
    requested_protocol = flask.request.args.get("protocol", None)
    indexed_file = IndexedFile(file_id)
    max_ttl = config.get("MAX_PRESIGNED_URL_TTL", 3600)
    expires_in = min(int(flask.request.args.get("expires_in", max_ttl)), max_ttl)
    signed_url = indexed_file.get_signed_url(requested_protocol, action, expires_in)
    return {"url": signed_url}


class BlankIndex(object):
    """
    Create a new blank record in indexd, to use for the data upload flow.

    See docs on data upload flow for further details:

        https://github.com/uc-cdis/cdis-wiki/tree/master/dev/gen3/data_upload
    """

    def __init__(self, uploader=None, file_name=None, logger=None):
        self.logger = logger or flask.current_app.logger
        self.indexd = (
            flask.current_app.config.get("INDEXD")
            or flask.current_app.config["BASE_URL"] + "/index"
        )
        self.uploader = uploader or current_token["context"]["user"]["name"]
        self.file_name = file_name

    @property
    def guid(self):
        """
        Return the GUID for this record in indexd.

        Currently the field in indexd is actually called ``did``.
        """
        return self.index_document["did"]

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
        auth = (config["INDEXD_USERNAME"], config["INDEXD_PASSWORD"])
        indexd_response = requests.post(index_url, json=params, auth=auth)
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
            flask.current_app.logger.error(
                "failed to reach indexd at {0}: {1}".format(url + self.file_id, e)
            )
            raise UnavailableError("Fail to reach id service to find data location")
        if res.status_code == 200:
            try:
                json_response = res.json()
                if "urls" not in json_response:
                    flask.current_app.logger.error(
                        "URLs are not included in response from "
                        "indexd: {}".format(url + self.file_id)
                    )
                    raise InternalError("URLs and metadata not found")
                return res.json()
            except Exception as e:
                flask.current_app.logger.error(
                    "indexd response missing JSON field {}".format(url + self.file_id)
                )
                raise InternalError("internal error from indexd: {}".format(e))
        elif res.status_code == 404:
            flask.current_app.logger.error(
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

    def get_signed_url(self, protocol, action, expires_in):
        if self.public and action == "upload":
            raise Unauthorized("Cannot upload on public files")
        # don't check the authorization if the file is public
        # (downloading public files with no auth is fine)
        if not self.public and not self.check_authorization(action):
            raise Unauthorized("You don't have access permission on this file")
        if action is not None and action not in SUPPORTED_ACTIONS:
            raise NotSupported("action {} is not supported".format(action))
        return self._get_signed_url(protocol, action, expires_in)

    def _get_signed_url(self, protocol, action, expires_in):
        if not protocol:
            # no protocol specified, return first location as signed url
            try:
                return self.indexed_file_locations[0].get_signed_url(
                    action, expires_in, public_data=self.public
                )
            except IndexError:
                raise NotFound("Can't find any file locations.")

        for file_location in self.indexed_file_locations:
            # allow file location to be https, even if they specific http
            if (file_location.protocol == protocol) or (
                protocol == "http" and file_location.protocol == "https"
            ):
                return file_location.get_signed_url(
                    action, expires_in, public_data=self.public
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

    @cached_property
    def metadata(self):
        return self.index_document.get("metadata", {})

    @cached_property
    def public(self):
        return check_public(self.set_acls)

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
            return self.index_document.get("uploader") == username

        if flask.g.token is None:
            given_acls = set(filter_auth_ids(action, flask.g.user.project_access))
        else:
            given_acls = set(
                filter_auth_ids(action, flask.g.token["context"]["user"]["projects"])
            )
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
            flask.current_app.boto.delete_data_file(bucket, self.file_id)

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

    def get_signed_url(self, action, expires_in, public_data=False):
        return self.url


class S3IndexedFileLocation(IndexedFileLocation):
    """
    An indexed file that lives in an AWS S3 bucket.
    """

    @classmethod
    def assume_role(cls, aws_creds, bucket_cred, cred_key, expires_in):
        role_arn = get_value(
            bucket_cred, "role-arn", InternalError("role-arn of that bucket is missing")
        )
        config = get_value(
            aws_creds,
            cred_key,
            InternalError("aws credential of that bucket is not found"),
        )
        assumed_role = flask.current_app.boto.assume_role(role_arn, expires_in, config)
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

    def get_credential_to_access_bucket(self, aws_creds, expires_in):
        s3_buckets = get_value(
            config, "S3_BUCKETS", InternalError("buckets not configured")
        )
        if len(aws_creds) == 0 and len(s3_buckets) == 0:
            raise InternalError("no bucket is configured")
        if len(aws_creds) == 0 and len(s3_buckets) > 0:
            raise InternalError("credential for buckets is not configured")

        bucket_cred = s3_buckets.get(self.bucket_name())
        if bucket_cred is None:
            raise Unauthorized("permission denied for bucket")

        cred_key = get_value(
            bucket_cred, "cred", InternalError("credential of that bucket is missing")
        )
        if cred_key == "*":
            return {"aws_access_key_id": "*"}

        if "role-arn" not in bucket_cred:
            return get_value(
                aws_creds,
                cred_key,
                InternalError("aws credential of that bucket is not found"),
            )
        else:
            return S3IndexedFileLocation.assume_role(
                aws_creds, bucket_cred, cred_key, expires_in
            )

    def get_signed_url(self, action, expires_in, public_data=False):
        aws_creds = get_value(
            config, "AWS_CREDENTIALS", InternalError("credentials not configured")
        )

        http_url = "https://{}.s3.amazonaws.com/{}".format(
            self.parsed_url.netloc, self.parsed_url.path.strip("/")
        )

        credential = self.get_credential_to_access_bucket(aws_creds, expires_in)

        aws_access_key_id = get_value(
            credential,
            "aws_access_key_id",
            InternalError("aws configuration not found"),
        )
        if aws_access_key_id == "*":
            return http_url

        region = flask.current_app.boto.get_bucket_region(
            self.parsed_url.netloc, credential
        )

        user_info = {}
        if not public_data:
            user_info = S3IndexedFileLocation.get_user_info()

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

    @staticmethod
    def get_user_info():
        user_info = {}
        set_current_token(validate_request(aud={"user"}))
        user_id = current_token["sub"]
        username = current_token["context"]["user"]["name"]
        if user_id is not None:
            user_info = {"user_id": str(user_id), "username": username}
        return user_info


class GoogleStorageIndexedFileLocation(IndexedFileLocation):
    """
    And indexed file that lives in a Google Storage bucket.
    """

    def get_signed_url(self, action, expires_in, public_data=False):
        resource_path = (
            self.parsed_url.netloc.strip("/") + "/" + self.parsed_url.path.strip("/")
        )

        # if the file is public, just return the public url to access it, no
        # signing required
        if public_data:
            url = "https://storage.googleapis.com/" + resource_path
        else:
            expiration_time = int(time.time()) + int(expires_in)
            url = self._generate_google_storage_signed_url(
                ACTION_DICT["gs"][action], resource_path, expiration_time
            )

        return url

    def _generate_google_storage_signed_url(
        self, http_verb, resource_path, expiration_time
    ):
        set_current_token(validate_request(aud={"user"}))
        user_id = current_token["sub"]
        proxy_group_id = get_or_create_proxy_group_id()
        username = current_token.get("context", {}).get("user", {}).get("name")

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

        final_url = cirrus.google_cloud.utils.get_signed_url(
            resource_path,
            http_verb,
            expiration_time,
            extension_headers=None,
            content_type="",
            md5_value="",
            service_account_creds=private_key,
        )
        return final_url


def filter_auth_ids(action, list_auth_ids):
    checked_permission = ""
    if action == "download":
        checked_permission = "read-storage"
    elif action == "upload":
        checked_permission = "write-storage"
    authorized_dbgaps = []
    for key, values in list_auth_ids.items():
        if checked_permission in values:
            authorized_dbgaps.append(key)
    return authorized_dbgaps


def check_public(set_acls):
    if "*" in set_acls:
        return True
