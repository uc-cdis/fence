"""
Fixtures to support tests/data
"""
import pytest


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
