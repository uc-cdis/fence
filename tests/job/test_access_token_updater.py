import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from fence.models import User
from fence.resources.openid.idp_oauth2 import Oauth2ClientBase as OIDCClient
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient

from fence.job.access_token_updater import AccessTokenUpdater


@pytest.fixture
def mock_db_session():
    """Fixture to mock the DB session."""
    return MagicMock()


@pytest.fixture
def mock_users():
    """Fixture to mock the user list."""
    user1 = MagicMock(spec=User)
    user1.username = "testuser1"
    user1.identity_provider.name = "ras"

    user2 = MagicMock(spec=User)
    user2.username = "testuser2"
    user2.identity_provider.name = "test_oidc"

    return [user1, user2]


@pytest.fixture
def mock_oidc_clients():
    """Fixture to mock OIDC clients."""
    ras_client = MagicMock(spec=RASClient)
    ras_client.idp = "ras"

    oidc_client = MagicMock(spec=OIDCClient)
    oidc_client.idp = "test_oidc"

    return [ras_client, oidc_client]


@pytest.fixture
def access_token_updater(mock_oidc_clients):
    """Fixture to instantiate AccessTokenUpdater with mocked OIDC clients."""
    # Patch the config to provide mock OIDC client configuration
    with patch("access_token_updater.config",
               {"OPENID_CONNECT": {"ras": {}, "test_oidc": {"groups": {"read_group_information": True}}},
                "CHECK_GROUPS": True}):
        updater = AccessTokenUpdater()
        updater.oidc_clients_requiring_token_refresh = mock_oidc_clients
        return updater


@pytest.mark.asyncio
async def test_get_user_from_db(access_token_updater, mock_db_session, mock_users):
    """Test the get_user_from_db method."""
    mock_db_session.query().slice().all.return_value = mock_users

    users = await access_token_updater.get_user_from_db(mock_db_session, chunk_idx=0)
    assert len(users) == 2
    assert users[0].username == "testuser1"
    assert users[1].username == "testuser2"


@pytest.mark.asyncio
async def test_producer(access_token_updater, mock_db_session, mock_users):
    """Test the producer method."""
    queue = asyncio.Queue()
    mock_db_session.query().slice().all.return_value = mock_users

    # Run producer to add users to queue
    await access_token_updater.producer(mock_db_session, queue, chunk_idx=0)

    assert queue.qsize() == len(mock_users)
    assert not queue.empty()

    # Dequeue to check correctness
    user = await queue.get()
    assert user.username == "testuser1"


@pytest.mark.asyncio
async def test_worker(access_token_updater, mock_users):
    """Test the worker method."""
    queue = asyncio.Queue()
    updater_queue = asyncio.Queue()

    # Add users to the queue
    for user in mock_users:
        await queue.put(user)

    # Run the worker to transfer users from queue to updater_queue
    await access_token_updater.worker("worker_1", queue, updater_queue)

    assert updater_queue.qsize() == len(mock_users)
    assert queue.empty()


@pytest.mark.asyncio
async def test_updater(access_token_updater, mock_users, mock_db_session, mock_oidc_clients):
    """Test the updater method."""
    updater_queue = asyncio.Queue()

    # Add a user to the updater_queue
    await updater_queue.put(mock_users[0])

    # Mock the client to return a valid update process
    mock_oidc_clients[0].update_user_authorization = AsyncMock()

    # Run the updater to process the user and update authorization
    await access_token_updater.updater("updater_1", updater_queue, mock_db_session)

    # Verify that the OIDC client was called with the correct user
    mock_oidc_clients[0].update_user_authorization.assert_called_once_with(
        mock_users[0],
        pkey_cache=access_token_updater.pkey_cache,
        db_session=mock_db_session,
    )


@pytest.mark.asyncio
async def test_no_client_found(access_token_updater, mock_users):
    """Test that updater does not crash if no client is found."""
    updater_queue = asyncio.Queue()

    # Modify the user to have an unrecognized identity provider
    mock_users[0].identity_provider.name = "unknown_provider"

    await updater_queue.put(mock_users[0])

    # Run the updater and ensure it skips the user with no client
    await access_token_updater.updater("updater_1", updater_queue, MagicMock())

    assert updater_queue.empty()  # The user should still be dequeued


@pytest.mark.asyncio
async def test_pick_client(access_token_updater, mock_users, mock_oidc_clients):
    """Test that the correct OIDC client is selected based on the user's IDP."""
    # Pick the client for a RAS user
    client = access_token_updater._pick_client(mock_users[0])
    assert client.idp == "ras"

    # Pick the client for a test OIDC user
    client = access_token_updater._pick_client(mock_users[1])
    assert client.idp == "test_oidc"

    # Ensure no client is returned for a user with no matching IDP
    mock_users[0].identity_provider.name = "nonexistent_idp"
    client = access_token_updater._pick_client(mock_users[0])
    assert client is None
