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
    User(username="user1", identity_provider=MagicMock(name="provider1")),
    User(username="user2", identity_provider=MagicMock(name="provider2")),
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

    # Start the update_tokens process with the mock db session
    await updater.update_tokens(db_session)


# Running the driver function in an asyncio loop
if __name__ == "__main__":
    asyncio.run(driver())
