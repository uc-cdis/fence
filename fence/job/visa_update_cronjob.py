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
        window_size=None,  #
        concurrency=None,  # number of concurrent users going through the visa update flow
        thread_pool_size=None,  # number of Docker container CPU used for jwt verification
        buffer_size=None,  # max size of asyncio queue
        logger=logger,
    ):
        """
        args:
            window_size: size of chunk of users we want to take from each iteration
            concurrency: number of concurrent users going through the visa update flow
            thread_pool_size: number of Docker container CPU used for jwt verifcation
            buffer_size: max size of queue
        """
        self.window_size = window_size or 8
        self.concurrency = concurrency or 2
        self.thread_pool_size = thread_pool_size or 2
        self.buffer_size = buffer_size or 10
        self.n_workers = self.thread_pool_size + self.concurrency
        self.logger = logger

    async def update_tokens(self, db_session):
        """
        Have dictionary or something to decide which client to use. Can go through the whole list and decide which client to use
        looking at the type field in the ga4gh table.
        """
        start_time = time.time()
        self.logger.info("Initializing Visa Update Cronjob . . .")
        self.logger.info("Total concurrency size: {}".format(self.concurrency))
        self.logger.info("Total thread pool size: {}".format(self.thread_pool_size))
        self.logger.info("Total buffer size: {}".format(self.buffer_size))
        self.logger.info("Total numbner of workers: {}".format(self.n_workers))

        queue = asyncio.Queue(maxsize=self.buffer_size)
        semaphore = asyncio.Queue(maxsize=self.n_workers)
        loop = asyncio.get_event_loop()

        producers = [
            loop.create_task(self.producer(db_session, queue, window_idx=0))
            for _ in range(1)
        ]
        workers = [
            loop.create_task(self.worker(j, queue, semaphore))
            for j in range(self.n_workers)
        ]
        updaters = [
            loop.create_task(self.updater(i, semaphore, db_session))
            for i in range(self.concurrency)
        ]

        await asyncio.gather(*producers)
        self.logger.info("Producers done producing")
        await queue.join()

        await asyncio.gather(*workers)
        await semaphore.join()  # blocks until everything in semaphore is complete

        for w in workers:
            w.cancel()
        for u in updaters:
            u.cancel()

        self.logger.info(
            "Visa cron job completed in {}".format(
                datetime.timedelta(seconds=time.time() - start_time)
            )
        )

    async def window(self, db_session, queue, window_idx):
        """
        window function to get chunks of data from the table
        """
        window_size = self.window_size
        start, stop = window_size * window_idx, window_size * (window_idx + 1)
        users = db_session.query(User).slice(start, stop).all()
        return users

    async def producer(self, db_session, queue, window_idx):
        """
        Produces users from db and puts them in a queue for processing
        """
        window_size = 8
        while True:
            users = await self.window(db_session, queue, window_idx)

            if users == None:
                break
            for user in users:
                self.logger.info("Producer producing user {}".format(user.username))
                await queue.put(user)
            if len(users) < window_size:
                break
            window_idx += 1

    async def worker(self, name, queue, semaphore):
        """
        Create tasks to pass tot updater to update visas AND pass updated visas to _verify_jwt_token for verification
        """
        while not queue.empty():
            user = await queue.get()
            await semaphore.put(user)
            queue.task_done()

    async def updater(self, name, semaphore, db_session):
        """
        Update visas in the semaphore
        """
        while True:
            user = await semaphore.get()
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

            semaphore.task_done()

    def _pick_client(self, visa):
        """
        Pick oidc client according to the visa provider
        """
        if "ras" in visa.type:
            oidc = config.get("OPENID_CONNECT", {})
            return RASClient(
                oidc["ras"],
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )

    def _verify_jwt_token(self, visa):
        # NOT IMPLEMENTED
        # TODO: Once local jwt verification is ready use thread_pool_size to determine how many users we want to verify the token for
        pass
