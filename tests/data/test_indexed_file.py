"""
Test fence.blueprints.data.indexd.IndexedFile
"""

import json
from unittest import mock
from mock import patch, MagicMock

import gen3cirrus
import pytest

import fence.blueprints.data.indexd as indexd
from fence.blueprints.data.indexd import (
    IndexedFile,
    GoogleStorageIndexedFileLocation,
    S3IndexedFileLocation,
)
from fence.models import (
    AssumeRoleCacheGCP,
    GoogleServiceAccountKey,
    UserGoogleAccountToProxyGroup,
)
import fence.resources.google.utils as utils


from fence.errors import (
    InternalError,
    Unauthorized,
    UnavailableError,
    NotFound,
    NotSupported,
)


def test_indexed_file_index_document_request_not_available(app):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to index_document with Unavailable Error
    """
    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.blueprints.data.indexd.requests.get",
            side_effect=Exception("url not available"),
        ):
            indexed_file = IndexedFile(file_id="some id")
            with pytest.raises(UnavailableError):
                print(indexed_file.index_document)


def test_indexed_file_index_document_request_has_json_exception(
    app, supported_protocol
):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to index_document with JSON ValueError
    """

    class MockResponse:
        """
        Mock response for requests lib
        """

        def __init__(self, data, status_code=200):
            """
            Setup mock response
            """
            self.data = data
            self.status_code = status_code

        def json(self):
            """
            Mock json() call with ValueError
            """
            raise ValueError("unable to get json")

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.blueprints.data.indexd.requests.get",
            return_value=MockResponse({"urls": [f"{supported_protocol}://some/url"]}),
        ):
            indexed_file = IndexedFile(file_id="some id")
            with pytest.raises(InternalError):
                indexed_file.index_document


def test_indexed_file_index_document_request_has_json(app, supported_protocol):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to index_document with JSON
    """

    class MockResponse:
        """
        Mock response for requests lib
        """

        def __init__(self, data, status_code=200):
            """
            Setup mock response
            """
            self.data = data
            self.status_code = status_code

        def json(self):
            """
            Mock json() call
            """
            return self.data

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.blueprints.data.indexd.requests.get",
            return_value=MockResponse({"urls": [f"{supported_protocol}://some/url"]}),
        ):
            indexed_file = IndexedFile(file_id="some id")
            assert indexed_file.index_document


def test_indexed_file_index_document_request_has_json_no_urls(app):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to index_document with JSON without URLs
    """

    class MockResponse:
        """
        Mock response for requests lib
        """

        def __init__(self, data, status_code=200):
            """
            Setup mock response
            """
            self.data = data
            self.status_code = status_code

        def json(self):
            """
            Mock json() call
            """
            return self.data

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.blueprints.data.indexd.requests.get",
            return_value=MockResponse({"not_urls": ["some url"]}),
        ):
            indexed_file = IndexedFile(file_id="some id")
            with pytest.raises(InternalError):
                indexed_file.index_document


def test_indexed_file_index_document_request_not_found(app):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to index_document with JSON not found
    """

    class MockResponse:
        """
        Mock response for requests lib
        """

        def __init__(self, data, status_code=404):
            """
            Setup mock response 404
            """
            self.data = data
            self.status_code = status_code

        def json(self):
            """
            Mock json() call
            """
            return self.data

        def text(self):
            """
            Mock text() call
            """
            return "Not Found"

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.blueprints.data.indexd.requests.get",
            return_value=MockResponse(data=None),
        ):
            indexed_file = IndexedFile(file_id="some id")
            with pytest.raises(NotFound):
                indexed_file.index_document


def test_indexed_file_index_document_request_service_not_available(app):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to index_document service not available
    """

    class MockResponse:
        """
        Mock response for requests lib
        """

        def __init__(self, data, status_code=503):
            """
            Setup mock response 503
            """
            self.data = data
            self.status_code = status_code

        def json(self):
            """
            Mock json() call
            """
            return self.data

        def text(self):
            """
            Mock text() call
            """
            return "Not Found"

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.blueprints.data.indexd.requests.get",
            return_value=MockResponse(data=None),
        ):
            indexed_file = IndexedFile(file_id="some id")
            with pytest.raises(UnavailableError):
                indexed_file.index_document


def test_indexed_file_locations(app, supported_protocol):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to indexed_file_locations success
    """

    class MockResponse:
        """
        Mock response for requests lib
        """

        def __init__(self, data, status_code=200):
            """
            Setup mock response 200
            """
            self.data = data
            self.status_code = status_code

        def json(self):
            """
            Mock json() call
            """
            return self.data

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.blueprints.data.indexd.requests.get",
            return_value=MockResponse({"urls": [f"{supported_protocol}://some/url"]}),
        ):
            indexed_file = IndexedFile(file_id="some id")
            assert indexed_file.indexed_file_locations


def test_get_signed_url_action_not_supported(
    app, supported_protocol, indexd_client_accepting_record
):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to get_signed_url action not supported
    """
    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        indexd_record_with_non_public_authz_and_public_acl_populated = {
            "urls": [f"{supported_protocol}://some/location"],
            "authz": None,
            "acl": ["*"],
        }
        indexd_client_accepting_record(
            indexd_record_with_non_public_authz_and_public_acl_populated
        )
        indexed_file = IndexedFile(file_id="some id")
        with pytest.raises(NotSupported):
            assert indexed_file.get_signed_url(
                protocol=supported_protocol, action="not_supported", expires_in=10
            )


@pytest.mark.parametrize(
    "supported_action", ["download", "not_supported"], indirect=True
)
def test_internal_get_signed_url_no_protocol_index_error(
    app, supported_action, supported_protocol, indexd_client_accepting_record
):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to get_signed_url
    without a protocol gives NotFound error
    """
    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "urls": [f"{supported_protocol}://some/location"],
        "authz": ["/programs/DEV/projects/test"],
        "acl": ["*"],
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        indexed_file = IndexedFile(file_id="some id")
        with patch(
            "fence.blueprints.data.indexd.IndexedFileLocation.get_signed_url",
            side_effect=IndexError(),
        ):
            with patch(
                "fence.blueprints.data.indexd.S3IndexedFileLocation.get_signed_url",
                side_effect=IndexError(),
            ):
                with patch(
                    "fence.blueprints.data.indexd.GoogleStorageIndexedFileLocation.get_signed_url",
                    side_effect=IndexError(),
                ):
                    with patch(
                        "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation.get_signed_url",
                        side_effect=IndexError(),
                    ):
                        with pytest.raises(NotFound):
                            indexed_file._get_signed_url(
                                protocol=None,
                                action=supported_action,
                                expires_in=10,
                                force_signed_url=True,
                                r_pays_project=None,
                                file_name="some file",
                            )


@pytest.mark.parametrize("supported_action", ["download"], indirect=True)
def test_internal_get_signed_url(
    app, supported_action, supported_protocol, indexd_client_accepting_record
):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to _get_signed_url is successful
    """
    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "urls": [f"{supported_protocol}://some/location"],
        "authz": ["/programs/DEV/projects/test"],
        "acl": ["*"],
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        indexed_file = IndexedFile(file_id="some id")
        with patch("fence.blueprints.data.indexd.IndexedFileLocation.get_signed_url"):
            with patch(
                "fence.blueprints.data.indexd.S3IndexedFileLocation.get_signed_url"
            ):
                with patch(
                    "fence.blueprints.data.indexd.GoogleStorageIndexedFileLocation.get_signed_url"
                ):
                    with patch(
                        "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation.get_signed_url"
                    ):
                        assert indexed_file._get_signed_url(
                            protocol=supported_protocol,
                            action=supported_action,
                            expires_in=10,
                            force_signed_url=True,
                            r_pays_project=None,
                            file_name="some file",
                        )


@patch("fence.blueprints.data.indexd.get_value")
def test_get_signed_url_s3_bucket_name(mock_get_value, s3_indexed_file_location, app):
    # Mock config with buckets for s3_buckets.get(bucket_name)
    mock_get_value.side_effect = lambda config, key, error: {
        "AWS_CREDENTIALS": {"aws_access_key_id": "mock_key"},
        "S3_BUCKETS": {
            "invalid_bucket*name": {"endpoint_url": "https://custom.endpoint.com"},
            "validbucketname-alreadyvalid": {
                "endpoint_url": "https://custom.endpoint2.com"
            },
        },
    }.get(key, error)

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        # patch get_credential_to_access_bucket() ensure get_signed_url can proceed without actually accessing AWS credentials
        with patch.object(
            S3IndexedFileLocation, "get_credential_to_access_bucket"
        ) as mock_get_credential:
            mock_get_credential.return_value = {
                "aws_access_key_id": "mock_key",
                "aws_secret_access_key": "mock_secret",  # pragma: allowlist secret
            }

            result_url = s3_indexed_file_location.get_signed_url(
                "download", expires_in=3600
            )

            # Check that real_bucket_name fell back to parsed_url.netloc, or otherwise used the already valid bucket
            if s3_indexed_file_location.bucket_name() == "invalid_bucket*name":
                assert "validbucketname-netloc" in result_url
            else:
                assert "validbucketname-alreadyvalid" in result_url


@pytest.mark.parametrize("supported_action", ["download"], indirect=True)
def test_internal_get_signed_url_no_location_match(
    app, supported_action, supported_protocol, indexd_client_accepting_record
):
    """
    Test fence.blueprints.data.indexd.IndexedFile call to _get_signed_url with location not found
    """
    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "urls": [f"{supported_protocol}://some/location"],
        "authz": ["/programs/DEV/projects/test"],
        "acl": ["*"],
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        indexed_file = IndexedFile(file_id="some id")
        with patch(
            "fence.blueprints.data.indexd.IndexedFile.indexed_file_locations",
            return_value=[],
        ):
            with pytest.raises(NotFound):
                indexed_file._get_signed_url(
                    protocol=supported_protocol,
                    action=supported_action,
                    expires_in=10,
                    force_signed_url=True,
                    r_pays_project=None,
                    file_name="some file",
                )


@mock.patch.object(utils, "_get_proxy_group_id", return_value=None)
@mock.patch.object(indexd, "get_or_create_proxy_group_id", return_value="1")
def test_internal_get_gs_signed_url_cache_new_key_if_old_key_expired(
    mock_get_or_create_proxy_group_id,
    mock_get_proxy_group_id,
    app,
    indexd_client_accepting_record,
    db_session,
):
    """
    Test fence.blueprints.data.indexd.GoogleStorageIndexedFileLocation._generate_google_storage_signed_url does not use cached key if its expired
    """
    db_session.add(
        AssumeRoleCacheGCP(
            gcp_proxy_group_id="1",
            expires_at=0,
            gcp_private_key="key",
            gcp_key_db_entry='{"1":("key", keydbentry)}',
        )
    )
    db_session.commit()

    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "urls": [f"gs://some/location"],
        "authz": ["/programs/DEV/projects/test"],
        "acl": ["*"],
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )

    mock_google_service_account_key = GoogleServiceAccountKey()
    mock_google_service_account_key.expires = 10
    mock_google_service_account_key.private_key = "key"
    sa_private_key = {
        "type": "service_account",
        "project_id": "project_id",
        "private_key": "pdashoidhaspidhaspidhiash",
    }

    with mock.patch(
        "fence.blueprints.data.indexd.get_or_create_primary_service_account_key",
        return_value=(sa_private_key, mock_google_service_account_key),
    ):
        with mock.patch(
            "fence.blueprints.data.indexd.create_primary_service_account_key",
            return_value=(sa_private_key),
        ):
            with mock.patch.object(
                gen3cirrus.google_cloud.utils,
                "get_signed_url",
                return_value="https://cloud.google.com/compute/url",
            ):
                indexed_file = IndexedFile(file_id="some id")
                google_object = GoogleStorageIndexedFileLocation("gs://some/location")
                google_object._assume_role_cache_gs = {"1": ("key", 10)}

                assert google_object._assume_role_cache_gs
                before_cache = db_session.query(AssumeRoleCacheGCP).first()

                google_object._generate_google_storage_signed_url(
                    http_verb="GET",
                    resource_path="gs://some/location",
                    expires_in=0,
                    user_id=1,
                    username="some user",
                    r_pays_project=None,
                )

                after_cache = db_session.query(AssumeRoleCacheGCP).all()
                assert before_cache != after_cache


@mock.patch.object(utils, "_get_proxy_group_id", return_value=None)
@mock.patch.object(indexd, "get_or_create_proxy_group_id", return_value="1")
def test_internal_get_gs_signed_url_clear_cache_and_parse_json(
    mock_get_or_create_proxy_group_id,
    mock_get_proxy_group_id,
    app,
    indexd_client_accepting_record,
    db_session,
):
    """
    Test fence.blueprints.data.indexd.GoogleStorageIndexedFileLocation._generate_google_storage_signed_url
    Scenario: - Create presigned url, cache in-mem and in db
              - Roll pods, which removes in-mem cache but keeps db entry
              - Make sure in-mem is populated correctly when creating presigned url again

    create presigned url
        set cache in db
    clear cache
    create presigned url again
        make sure cache is set correctly
    """

    indexd_record_with_non_public_authz_and_public_acl_populated = {
        "urls": [f"gs://some/location"],
        "authz": ["/programs/DEV/projects/test"],
        "acl": ["*"],
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_public_acl_populated
    )

    mock_google_service_account_key = GoogleServiceAccountKey()
    mock_google_service_account_key.expires = 10
    mock_google_service_account_key.private_key = "key"
    sa_private_key = {
        "type": "service_account",
        "project_id": "project_id",
        "private_key": "pdashoidhaspidhaspidhiash",
    }

    with mock.patch(
        "fence.blueprints.data.indexd.get_or_create_primary_service_account_key",
        return_value=(sa_private_key, mock_google_service_account_key),
    ):
        with mock.patch(
            "fence.blueprints.data.indexd.create_primary_service_account_key",
            return_value=(sa_private_key),
        ):
            with mock.patch.object(
                gen3cirrus.google_cloud.utils,
                "get_signed_url",
                return_value="https://cloud.google.com/compute/url",
            ):
                indexed_file = IndexedFile(file_id="some id")
                google_object = GoogleStorageIndexedFileLocation("gs://some/location")
                google_object._assume_role_cache_gs = {"1": ("key", 10)}

                before_cache = db_session.query(AssumeRoleCacheGCP).first()

                google_object._generate_google_storage_signed_url(
                    http_verb="GET",
                    resource_path="gs://some/location",
                    expires_in=0,
                    user_id=1,
                    username="some user",
                    r_pays_project=None,
                )

                assert google_object._assume_role_cache_gs["1"][0] == sa_private_key

                after_cache = db_session.query(AssumeRoleCacheGCP).first()

                assert after_cache
                # check if json loads can properly parse json string stored in cache
                assert "1" in google_object._assume_role_cache_gs
                assert len(google_object._assume_role_cache_gs["1"]) > 1
                assert google_object._assume_role_cache_gs["1"][0] == sa_private_key

                # make sure cache is added back in the proper format after clearing
                google_object._assume_role_cache_gs = {}

                google_object._generate_google_storage_signed_url(
                    http_verb="GET",
                    resource_path="gs://some/location",
                    expires_in=0,
                    user_id=1,
                    username="some user",
                    r_pays_project=None,
                )

                redo_cache = db_session.query(AssumeRoleCacheGCP).first()

                assert redo_cache
                # check if json loads can properly parse json string stored in cache
                assert "1" in google_object._assume_role_cache_gs
                assert len(google_object._assume_role_cache_gs["1"]) > 1
                assert google_object._assume_role_cache_gs["1"][0] == sa_private_key


def test_set_acl_missing_unauthorized(
    app, supported_protocol, indexd_client_accepting_record
):
    """
    Test fence.blueprints.data.indexd.IndexedFile set_acls as unauthorized from indexd record
    """
    indexd_record_with_non_public_authz_and_no_public_acl_populated = {
        "urls": [f"{supported_protocol}://some/location"],
        "authz": ["/programs/DEV/projects/test"],
        "noacl": [],
    }
    indexd_client_accepting_record(
        indexd_record_with_non_public_authz_and_no_public_acl_populated
    )

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        indexed_file = IndexedFile(file_id="some id")
        with pytest.raises(Unauthorized):
            indexed_file.set_acls


def test_get_authorized_with_username_missing_value_error(
    app, supported_action, supported_protocol, indexd_client_accepting_record
):
    """
    Test fence.blueprints.data.indexd.IndexedFile get_authorized_with_username without authz in indexd record
    """
    indexd_record_with_no_authz_and_public_acl_populated = {
        "urls": [f"{supported_protocol}://some/location"],
        "noauthz": ["/programs/DEV/projects/test"],
        "acl": [],
    }
    indexd_client_accepting_record(indexd_record_with_no_authz_and_public_acl_populated)

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        indexed_file = IndexedFile(file_id="some id")
        with pytest.raises(ValueError):
            indexed_file.get_authorized_with_username(supported_action)


@pytest.mark.parametrize(
    "public_bucket_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az"],
    indirect=True,
)
def test_delete_files_unable_to_get_file_name(app, public_bucket_indexd_client):
    """
    Test fence.blueprints.data.indexd.IndexedFile delete_files with missing file name
    """

    class MockBlobServiceClient:
        """
        Mock Blob Service Client
        """

        def __init__(self, conn_str):
            """
            Setup MockBlobServiceClient
            """
            self.conn_str = conn_str

        def get_blob_client(self, container_name, blob_name):
            """
            Get a MockBlobClient
            """
            return MockBlobClient(container_name=container_name, blob_name=blob_name)

    class MockBlobClient:
        """
        Mock Blob Client
        """

        def __init__(self, container_name, blob_name):
            """
            Setup MockBlobClient
            """
            self.container_name = container_name
            self.blob_name = blob_name

        def delete_blob(self):
            """
            Mock delete_blob to raise Exception
            """
            raise Exception("url not available")

    with patch(
        "fence.blueprints.data.indexd.S3IndexedFileLocation.file_name",
        side_effect=Exception("url not available"),
    ):
        with patch(
            "fence.blueprints.data.indexd.GoogleStorageIndexedFileLocation.file_name",
            side_effect=Exception("url not available"),
        ):
            with patch(
                "fence.blueprints.data.indexd.AzureBlobStorageIndexedFileLocation.file_name",
                side_effect=Exception("url not available"),
            ):
                with patch(
                    "fence.resources.user.user_session.UserSession.create_initial_token"
                ):
                    with patch(
                        "fence.blueprints.data.indexd.flask.current_app.boto.delete_data_file",
                        side_effect=Exception("url not available"),
                    ):
                        with patch(
                            "gen3cirrus.GoogleCloudManager.delete_data_file",
                            side_effect=Exception("url not available"),
                        ):
                            with patch(
                                "fence.blueprints.data.indexd.BlobServiceClient.from_connection_string",
                                return_value=MockBlobServiceClient(
                                    conn_str="some_connection_string"
                                ),
                            ):
                                indexed_file = IndexedFile(file_id="some id")
                                assert indexed_file.delete_files()


@pytest.mark.parametrize(
    "public_bucket_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az"],
    indirect=True,
)
def test_delete_files_successful(app, public_bucket_indexd_client):
    """
    Test fence.blueprints.data.indexd.IndexedFile delete_files is successful
    """

    class MockBlobServiceClient:
        """
        Mock Blob Service Client
        """

        def __init__(self, conn_str):
            """
            Setup MockBlobServiceClient
            """
            self.conn_str = conn_str

        def get_blob_client(self, container_name, blob_name):
            """
            Get a MockBlobClient
            """
            return MockBlobClient(container_name=container_name, blob_name=blob_name)

    class MockBlobClient:
        """
        Mock Blob Client
        """

        def __init__(self, container_name, blob_name):
            """
            Setup MockBlobClient
            """
            self.container_name = container_name
            self.blob_name = blob_name

        def delete_blob(self):
            """
            Delete a blob
            """
            return

    with patch("fence.resources.user.user_session.UserSession.create_initial_token"):
        with patch(
            "fence.blueprints.data.indexd.flask.current_app.boto.delete_data_file",
            return_value=("", 204),
        ):
            with patch(
                "gen3cirrus.GoogleCloudManager.delete_data_file",
                return_value=("", 204),
            ):
                with patch(
                    "fence.blueprints.data.indexd.BlobServiceClient.from_connection_string",
                    return_value=MockBlobServiceClient(
                        conn_str="some_connection_string"
                    ),
                ):
                    indexed_file = IndexedFile(file_id="some id")
                    assert indexed_file.delete_files()


@pytest.mark.parametrize(
    "public_bucket_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az"],
    indirect=True,
)
def test_delete_files_fails_invalid_connection_string(app, public_bucket_indexd_client):
    """
    Test fence.blueprints.data.indexd.IndexedFile delete_files fails
    because of an invalid connection string
    """

    class MockBlobServiceClient:
        """
        Mock Blob Service Client
        """

        def __init__(self, conn_str):
            """
            Setup MockBlobServiceClient
            """
            self.conn_str = conn_str

        @classmethod
        def from_connection_string(cls, container_name, blob_name):
            """
            Get a MockBlobClient
            """
            raise ValueError("Connection string is either blank or malformed.")

    with patch("fence.resources.user.user_session.UserSession.create_initial_token"):
        with patch(
            "fence.blueprints.data.indexd.flask.current_app.boto.delete_data_file",
            side_effect=ValueError("Invalid connection string"),
        ):
            with patch(
                "gen3cirrus.GoogleCloudManager.delete_data_file",
                side_effect=ValueError("Invalid connection string"),
            ):
                with patch(
                    "fence.blueprints.data.indexd.BlobServiceClient.from_connection_string",
                    return_value=MockBlobServiceClient(
                        conn_str="invalid connection string"
                    ),
                ):
                    indexed_file = IndexedFile(file_id="some id")
                    message, status_code = indexed_file.delete_files()
                    assert message == "Failed to delete data file."
                    assert status_code == 500


@pytest.mark.parametrize(
    "public_bucket_indexd_client",
    ["gs", "s3", "gs_acl", "s3_acl", "az"],
    indirect=True,
)
def test_delete_call_not_successful(app, public_bucket_indexd_client):
    """
    Test fence.blueprints.data.indexd.IndexedFile delete_files fails
    """

    class MockResponse:
        """
        Mock Response from requests lib
        """

        def __init__(self, data, status_code=200):
            """
            Setup Mock Response
            """
            self.data = data
            self.status_code = status_code

        def json(self):
            """
            Mock json() call
            """
            return self.data

    with patch("fence.resources.user.user_session.UserSession.create_initial_token"):
        with patch(
            "fence.blueprints.data.indexd.requests.delete",
            return_value=MockResponse(data=None, status_code=503),
        ):
            indexed_file = IndexedFile(file_id="some id")
            assert indexed_file.delete()
