import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch, MagicMock
from fence.models import User, UpstreamRefreshToken, create_user
from fence.resources.openid.idp_oauth2 import Oauth2ClientBase as OIDCClient
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient
from fence.job.access_token_updater import TokenAndAuthUpdater


@pytest.fixture(scope="session", autouse=True)
def event_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture
def run_async(event_loop):
    """Run an async coroutine in the current event loop."""

    def _run(coro):
        return event_loop.run_until_complete(coro)

    return _run


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
def access_token_updater_config(mock_oidc_clients):
    """Fixture to instantiate TokenAndAuthUpdater with mocked OIDC clients."""
    with patch(
        "fence.config",
        {
            "OPENID_CONNECT": {
                "ras": {},
                "test_oidc": {"groups": {"read_authz_groups_from_tokens": True}},
            },
            "ENABLE_AUTHZ_GROUPS_FROM_OIDC": True,
        },
    ):
        updater = TokenAndAuthUpdater()

        # Ensure this is a dictionary rather than a list
        updater.oidc_clients_requiring_token_refresh = {
            client.idp: client for client in mock_oidc_clients
        }

        return updater


def _add_user(db_session, username, idp_name=None, token_expires=()):
    """Create a real user with the given IdP and one refresh token per expiry."""
    user = create_user(db_session, MagicMock(), username, idp_name=idp_name)
    for i, expires in enumerate(token_expires):
        db_session.add(
            UpstreamRefreshToken(
                user=user, refresh_token=f"{username}-rt-{i}", expires=expires
            )
        )
    db_session.commit()
    return user


@pytest.fixture
def refreshable_users_db(db_session):
    """
    Users covering every case get_user_from_db has to filter. The updater under
    test is configured with clients for "ras" and "test_oidc" only.
    """
    db_session.query(UpstreamRefreshToken).delete()
    db_session.query(User).delete()
    db_session.commit()

    future = int(time.time()) + 3600
    users = {
        "ras_with_token_1": _add_user(db_session, "ras_with_token_1", "ras", [future]),
        "ras_no_token": _add_user(db_session, "ras_no_token", "ras"),
        "google_with_token": _add_user(
            db_session, "google_with_token", "google", [future]
        ),
        "no_idp_with_token": _add_user(db_session, "no_idp_with_token", None, [future]),
        "oidc_with_token": _add_user(
            db_session, "oidc_with_token", "test_oidc", [future]
        ),
        "ras_with_token_2": _add_user(db_session, "ras_with_token_2", "ras", [future]),
    }
    return users


REFRESHABLE_IN_ID_ORDER = ["ras_with_token_1", "oidc_with_token", "ras_with_token_2"]


def test_get_user_from_db_only_returns_refreshable_users(
    run_async, access_token_updater_config, db_session, refreshable_users_db
):
    """
    Only users whose IdP has a refresh client and who have a stored refresh token
    are returned, in id order.
    """
    access_token_updater_config.chunk_size = 100
    users = run_async(access_token_updater_config.get_user_from_db(db_session))
    assert [u.username for u in users] == REFRESHABLE_IN_ID_ORDER


def test_get_user_from_db_keyset_pagination_survives_deletes(
    run_async, access_token_updater_config, db_session, refreshable_users_db
):
    """
    Removing a returned user's tokens between pages must not skip the next user,
    which offset pagination would do.
    """
    updater = access_token_updater_config
    updater.chunk_size = 1

    page_1 = run_async(updater.get_user_from_db(db_session, 0))
    assert [u.username for u in page_1] == ["ras_with_token_1"]
    last_id = page_1[0].id

    # e.g. get_access_token / invalid_grant deleting the user's only token mid-run
    db_session.query(UpstreamRefreshToken).filter(
        UpstreamRefreshToken.user_id == last_id
    ).delete()
    db_session.commit()

    page_2 = run_async(updater.get_user_from_db(db_session, last_id))
    assert [u.username for u in page_2] == ["oidc_with_token"]


def test_producer(
    run_async, access_token_updater_config, db_session, refreshable_users_db
):
    """The producer pages through and enqueues exactly the refreshable users."""
    access_token_updater_config.chunk_size = 2  # forces multiple pages
    queue = asyncio.Queue()

    run_async(access_token_updater_config.producer(db_session, queue))

    produced = []
    while not queue.empty():
        produced.append(run_async(queue.get()).username)
    assert produced == REFRESHABLE_IN_ID_ORDER


def test_producer_no_refresh_clients(
    run_async, access_token_updater_config, db_session, refreshable_users_db
):
    """With no clients configured, nothing is produced."""
    access_token_updater_config.oidc_clients_requiring_token_refresh = {}
    queue = asyncio.Queue()
    run_async(access_token_updater_config.producer(db_session, queue))
    assert queue.empty()


def test_delete_expired_refresh_tokens(access_token_updater_config, db_session):
    """
    Expired tokens are deleted in bulk, valid ones kept, and the affected users are
    logged once at WARNING.
    """
    db_session.query(UpstreamRefreshToken).delete()
    db_session.query(User).delete()
    db_session.commit()

    now = int(time.time())
    mixed = _add_user(db_session, "mixed", "ras", [now - 10, now + 3600])
    expired_only = _add_user(db_session, "expired_only", "ras", [now - 10])
    valid_only = _add_user(db_session, "valid_only", "ras", [now + 3600])

    updater = access_token_updater_config
    updater.logger = MagicMock()
    updater._delete_expired_refresh_tokens(db_session)

    remaining = {
        (row.user.username, row.expires > now)
        for row in db_session.query(UpstreamRefreshToken).all()
    }
    assert remaining == {("mixed", True), ("valid_only", True)}

    updater.logger.warning.assert_called_once()
    message = updater.logger.warning.call_args[0][0]
    assert "2 expired upstream refresh token(s)" in message
    assert "expired_only" in message and "mixed" in message
    assert "valid_only" not in message


def test_delete_expired_refresh_tokens_nothing_expired(
    access_token_updater_config, db_session
):
    """No expired tokens: nothing deleted, nothing logged."""
    db_session.query(UpstreamRefreshToken).delete()
    db_session.query(User).delete()
    db_session.commit()
    _add_user(db_session, "valid_only", "ras", [int(time.time()) + 3600])

    updater = access_token_updater_config
    updater.logger = MagicMock()
    updater._delete_expired_refresh_tokens(db_session)

    assert db_session.query(UpstreamRefreshToken).count() == 1
    updater.logger.warning.assert_not_called()


def test_worker(run_async, access_token_updater_config, mock_users):
    """Test the worker method."""
    queue = asyncio.Queue()
    updater_queue = asyncio.Queue()

    # Add users to the queue
    for user in mock_users:
        run_async(queue.put(user))

    # Run the worker to transfer users from queue to updater_queue
    run_async(access_token_updater_config.worker("worker_1", queue, updater_queue))

    assert updater_queue.qsize() == len(mock_users)
    assert queue.empty()


async def updater_with_timeout(updater, queue, db_session, timeout=5):
    return await asyncio.wait_for(updater(queue, db_session), timeout)


def test_updater(
    run_async,
    access_token_updater_config,
    mock_users,
    mock_db_session,
    mock_oidc_clients,
):
    """Test the updater method."""
    updater_queue = asyncio.Queue()

    # Add a user to the updater_queue
    run_async(updater_queue.put(mock_users[0]))

    # Mock the client to return a valid update process
    mock_oidc_clients[0].update_user_authorization = MagicMock()

    # Ensure _pick_client returns the correct client
    with patch.object(
        access_token_updater_config, "_pick_client", return_value=mock_oidc_clients[0]
    ):
        # Signal the updater to stop after processing
        run_async(updater_queue.put(None))  # This should be an awaited call

        # Run the updater to process the user and update authorization
        run_async(
            access_token_updater_config.updater(
                "updater_1", updater_queue, mock_db_session
            )
        )

    # Verify that the OIDC client was called with the correct user
    mock_oidc_clients[0].update_user_authorization.assert_called_once_with(
        mock_users[0],
        pkey_cache=access_token_updater_config.pkey_cache,
        db_session=mock_db_session,
    )


def test_no_client_found(run_async, access_token_updater_config, mock_users):
    """Test that updater does not crash if no client is found."""
    updater_queue = asyncio.Queue()

    # Modify the user to have an unrecognized identity provider
    mock_users[0].identity_provider.name = "unknown_provider"

    run_async(updater_queue.put(mock_users[0]))  # Ensure this is awaited
    run_async(updater_queue.put(None))  # Signal the updater to terminate

    # Mock the client selection to return None
    with patch.object(access_token_updater_config, "_pick_client", return_value=None):
        # Run the updater and ensure it skips the user with no client
        run_async(
            access_token_updater_config.updater("updater_1", updater_queue, MagicMock())
        )

    assert updater_queue.empty()  # The user should still be dequeued


def test_pick_client(
    run_async, access_token_updater_config, mock_users, mock_oidc_clients
):
    """Test that the correct OIDC client is selected based on the user's IDP."""
    # Pick the client for a RAS user
    client = access_token_updater_config._pick_client(mock_users[0])
    assert client.idp == "ras"

    # Pick the client for a test OIDC user
    client = access_token_updater_config._pick_client(mock_users[1])
    assert client.idp == "test_oidc"

    # Ensure no client is returned for a user with no matching IDP
    mock_users[0].identity_provider.name = "nonexistent_idp"
    client = access_token_updater_config._pick_client(mock_users[0])
    assert client is None
