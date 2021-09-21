"""
Test fence.blueprints.data.indexd.IndexedFile
"""
from mock import patch

import pytest

from fence.blueprints.data.indexd import IndexedFile

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


def test_check_authz_missing_value_error(
    app, supported_action, supported_protocol, indexd_client_accepting_record
):
    """
    Test fence.blueprints.data.indexd.IndexedFile check_authz without authz in indexd record
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
            indexed_file.check_authz(supported_action)


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

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
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
                                "cirrus.GoogleCloudManager.delete_data_file",
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

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.resources.user.user_session.UserSession.create_initial_token"
        ):
            with patch(
                "fence.blueprints.data.indexd.flask.current_app.boto.delete_data_file",
                return_value=("", 204),
            ):
                with patch(
                    "cirrus.GoogleCloudManager.delete_data_file", return_value=("", 204)
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

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.resources.user.user_session.UserSession.create_initial_token"
        ):
            with patch(
                "fence.blueprints.data.indexd.flask.current_app.boto.delete_data_file",
                side_effect=ValueError("Invalid connection string"),
            ):
                with patch(
                    "cirrus.GoogleCloudManager.delete_data_file",
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

    with patch("fence.blueprints.data.indexd.flask.current_app", return_value=app):
        with patch(
            "fence.resources.user.user_session.UserSession.create_initial_token"
        ):
            with patch(
                "fence.blueprints.data.indexd.requests.delete",
                return_value=MockResponse(data=None, status_code=503),
            ):
                indexed_file = IndexedFile(file_id="some id")
                assert indexed_file.delete()
