import asyncio
import datetime
import time

from cdislogging import get_logger
from userdatamodel.driver import SQLAlchemyDriver

from fence.config import config
from fence.models import (
    GA4GHVisaV1,
    User,
    UpstreamRefreshToken,
    query_for_user,
)
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient


logger = get_logger(__name__, log_level="debug")


class Visa_Token_Update(object):
    def __init__(
        self,
        chunk_size=None,
        concurrency=None,
        thread_pool_size=None,
        buffer_size=None,
        logger=logger,
    ):
        """
        args:
            chunk_size: size of chunk of users we want to take from each iteration
            concurrency: number of concurrent users going through the visa update flow
            thread_pool_size: number of Docker container CPU used for jwt verifcation
            buffer_size: max size of queue
        """
        self.chunk_size = chunk_size or 10
        self.concurrency = concurrency or 5
        self.thread_pool_size = thread_pool_size or 2
        self.buffer_size = buffer_size or 10
        self.n_workers = self.thread_pool_size + self.concurrency
        self.logger = logger

        # Initialize visa clients:
        oidc = config.get("OPENID_CONNECT", {})
        if "ras" not in oidc:
            self.logger.error("RAS client not configured")
        else:
            self.ras_client = RASClient(
                    oidc["ras"],
                    HTTP_PROXY=config.get("HTTP_PROXY"),
                    logger=logger,
                )

    async def update_tokens(self, db_session):
        """
        Initialize a producer-consumer workflow.

        Producer: Collects users from db and feeds it to the workers
        Worker: Takes in the users from the Producer and passes it to the Updater to update the tokens and passes those updated tokens for JWT validation
        Updater: Updates refresh_tokens and visas

        """
        start_time = time.time()
        self.logger.info("Initializing Visa Update Cronjob . . .")
        self.logger.info("Total concurrency size: {}".format(self.concurrency))
        self.logger.info("Total thread pool size: {}".format(self.thread_pool_size))
        self.logger.info("Total buffer size: {}".format(self.buffer_size))
        self.logger.info("Total number of workers: {}".format(self.n_workers))

        queue = asyncio.Queue(maxsize=self.buffer_size)
        updater_queue = asyncio.Queue(maxsize=self.n_workers)
        loop = asyncio.get_event_loop()

        producers = [
            loop.create_task(self.producer(db_session, queue, chunk_idx=0))
            for _ in range(1)
        ]
        workers = [
            loop.create_task(self.worker(j, queue, updater_queue))
            for j in range(self.n_workers)
        ]
        updaters = [
            loop.create_task(self.updater(i, updater_queue, db_session))
            for i in range(self.concurrency)
        ]

        await asyncio.gather(*producers)
        self.logger.info("Producers done producing")
        await queue.join()

        await asyncio.gather(*workers)
        await updater_queue.join()  # blocks until everything in updater_queue is complete

        for u in updaters:
            u.cancel()
            
        self.logger.info(
            "Visa cron job completed in {}".format(
                datetime.timedelta(seconds=time.time() - start_time)
            )
        )

    async def get_user_from_db(self, db_session, queue, chunk_idx):
        """
        Window function to get chunks of data from the table
        """
        start, stop = self.chunk_size * chunk_idx, self.chunk_size * (chunk_idx + 1)
        users = db_session.query(User).slice(start, stop).all()
        return users

    async def producer(self, db_session, queue, chunk_idx):
        """
        Produces users from db and puts them in a queue for processing
        """
        chunk_size = self.chunk_size
        while True:
            users = await self.get_user_from_db(db_session, queue, chunk_idx)

            if users == None:
                break
            for user in users:
                self.logger.info("Producer producing user {}".format(user.username))
                await queue.put(user)
            if len(users) < chunk_size:
                break
            chunk_idx += 1

    async def worker(self, name, queue, updater_queue):
        """
        Create tasks to pass to updater to update visas AND pass updated visas to _verify_jwt_token for verification
        """
        while not queue.empty():
            user = await queue.get()
            await updater_queue.put(user)
            queue.task_done()

    async def updater(self, name, updater_queue, db_session):
        """
        Update visas in the updater_queue
        """
        while True:
            user = await updater_queue.get()
            if user.ga4gh_visas_v1:
                for visa in user.ga4gh_visas_v1:
                    client = self._pick_client(visa)
                    self.logger.info(
                        "Updater {} updating visa for user {}".format(
                            name, user.username
                        )
                    )
                    client.update_user_visas(user, db_session)
            else:
                self.logger.info(
                    "User {} doesnt have visa. Skipping . . .".format(user.username)
                )

            updater_queue.task_done()

    def _pick_client(self, visa):
        """
        Pick oidc client according to the visa provider
        """
        if "ras" in visa.type:
            return self.ras_client

    def _verify_jwt_token(self, visa):
        # NOT IMPLEMENTED
        # TODO: Once local jwt verification is ready use thread_pool_size to determine how many users we want to verify the token for
        pass
