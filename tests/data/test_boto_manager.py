import pytest
from unittest.mock import MagicMock, patch
from fence.resources.aws.boto_manager import BotoManager


class TestData:
    """Generate bucket test data that aims to mirror the default example Fence config file."""
    def __init__(self):
        self.config = {}
        self.buckets = {}

    def single_bucket(self):
        self.config = {
            'CRED1': {'access_key': 'key1', 'secret_key': 'secret1'},
        }
        self.buckets = {
            'bucket1': {'cred': 'CRED1', 'region': 'us-east-1', 'endpoint_url': 'https://example.com'},
        }
        return self

    def multiple_buckets(self):
        single_bucket = self.single_bucket()
        self.config = single_bucket.config | {
            'CRED2': {'access_key': 'key2', 'secret_key': 'secret2'},
        }
        self.buckets = single_bucket.buckets | {
            'bucket2': {'cred': 'CRED2', 'region': 'us-east-1'},
            'bucket3': {'cred': '*'},
            'bucket4': {'cred': 'CRED1', 'region': 'us-east-1', 'role-arn': 'arn:aws:iam::role1'}
        }
        return self


@patch('fence.resources.aws.boto_manager.client')
def test_create_s3_client_single(mock_client):
    test_data = TestData().single_bucket()
    config = test_data.config
    buckets = test_data.buckets
    logger = MagicMock()
    boto_manager = BotoManager(config, buckets, logger)

    s3_clients = boto_manager.create_s3_clients(config, buckets)

    # Assert that the correct call was made to the client function
    mock_client.assert_any_call('s3', access_key='key1', secret_key='key1', endpoint_url='https://example.com')

    # Assert that the returned dictionary contains the correct client
    assert len(s3_clients) == 1
    assert 'bucket1' in s3_clients


@patch('fence.resources.aws.boto_manager.client')
def test_create_s3_clients_multiple(mock_client):
    test_data = TestData().multiple_buckets()
    config = test_data.config
    buckets = test_data.buckets
    logger = MagicMock()
    boto_manager = BotoManager(config, buckets, logger)

    # Call the method under test
    s3_clients = boto_manager.create_s3_clients(config, buckets)

    # Assert that the correct calls were made to the client function
    mock_client.assert_any_call('s3', access_key='key1', secret_key='secret1', endpoint_url='https://example.com')
    mock_client.assert_any_call('s3', access_key='key2', secret_key='secret2')
    mock_client.assert_any_call('s3')
    mock_client.assert_any_call('s3', access_key='key1', secret_key='secret1')

    # Assert that the returned dictionary contains the correct clients
    assert len(s3_clients) == 4
    assert 'bucket1' in s3_clients
    assert 'bucket2' in s3_clients
    assert 'bucket3' in s3_clients
    assert 'bucket4' in s3_clients


@pytest.mark.parametrize("bucket", ['bucket1', 'bucket2', 'bucket3', 'bucket4'])
@patch('fence.resources.aws.boto_manager.client')
def test_delete_data_file(mock_client, bucket):
    test_data = TestData().multiple_buckets()
    config = test_data.config
    buckets = test_data.buckets
    logger = MagicMock()
    boto_manager = BotoManager(config, buckets, logger)

    # Mock the response of list_objects_v2 to include the desired key
    prefix = 'data/file.txt'
    mock_list_objects_v2_response = {
        'Contents': [{'Key': prefix}]
    }
    # Set up the mock S3 client and its list_objects_v2 and delete_object methods
    mock_s3_client = mock_client.return_value
    mock_s3_client.list_objects_v2.return_value = mock_list_objects_v2_response

    result = boto_manager.delete_data_file(bucket, prefix)

    # Create S3 clients for each of the buckets
    _ = boto_manager.create_s3_clients(config, buckets)
    s3_client = boto_manager.get_s3_client(bucket)
    s3_client.list_objects_v2.assert_called_once_with(
        Bucket=bucket, Prefix=prefix, Delimiter="/"
    )
    s3_client.delete_object.assert_called_once_with(Bucket=bucket, Key='data/file.txt')

    # Assert the expected result
    assert result == ("", 204)
