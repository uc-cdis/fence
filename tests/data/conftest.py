"""
Fixtures to support tests/data
"""
import pytest
from unittest.mock import MagicMock
from fence.blueprints.data.indexd import S3IndexedFileLocation


@pytest.fixture(scope="function", params=("upload", "download"))
def supported_action(request):
    """
    return "upload", "download"
    """

    return request.param


@pytest.fixture(scope="function", params=("s3", "http", "ftp", "https", "gs", "az"))
def supported_protocol(request):
    """
    return "s3", "http", "ftp", "https", "gs", "az"

    Note that "az" is an internal mapping for a supported protocol
    """
    return request.param


@pytest.fixture(
    params=[
        "invalid_bucket*name",
        "validbucketname-alreadyvalid",
        "validbucketname-netloc",
    ]
)
def s3_indexed_file_location(request):
    """
    Provides a mock s3 file location instance, parameterized with a valid and invalid bucket_name
    """
    mock_url = "only/needed/for/instantiation"
    location = S3IndexedFileLocation(url=mock_url)

    # Mock parsed_url attributes
    location.parsed_url = MagicMock()
    location.parsed_url.netloc = request.param
    location.parsed_url.path = "/test/object"

    return location
