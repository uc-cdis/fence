import asyncio
from unittest.mock import MagicMock
from sqlalchemy.orm import Session
from fence.job.visa_update_cronjob import Visa_Token_Updater

# Mocking dependencies
from fence.models import User

# Create a mock database session
db_session = MagicMock(spec=Session)

# Creating mock users in the database
mock_users = [
    User(username="user1", identity_provider=MagicMock(name="fence")),
    User(username="user2", identity_provider=MagicMock(name="keycloak")),
    User(username="user3", identity_provider=MagicMock(name="provider3")),
]

logger = MagicMock()

# Mocking query return
db_session.query().slice().all.return_value = mock_users


# Define a driver function
async def driver():
    # Instantiate the Visa_Token_Updater with mock parameters
    updater = Visa_Token_Updater(
        chunk_size=5,
        concurrency=3,
        thread_pool_size=2,
        buffer_size=5,
        logger=logger,
    )

    # Mock OIDC clients requiring token refresh
    mock_oidc_clients = [
        MagicMock(idp="keycloak"),
        MagicMock(idp="fence"),
    ]

    # Assign the OIDC clients to the updater instance
    updater.oidc_clients_requiring_token_refresh = mock_oidc_clients

    # Override the _pick_client method to see its effect
    def mock_pick_client(user):
        client = None
        for oidc_client in updater.oidc_clients_requiring_token_refresh:
            if getattr(user.identity_provider, "name") == oidc_client.idp:
                client = oidc_client
                logger.info(f"Picked client for {user.username}: {oidc_client.idp}")
        return client

    updater._pick_client = mock_pick_client

    # Start the update_tokens process with the mock db session
    await updater.update_tokens(db_session)


# Running the driver function in an asyncio loop
if __name__ == "__main__":
    asyncio.run(driver())
