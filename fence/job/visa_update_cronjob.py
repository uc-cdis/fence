import asyncio

from cdislogging import get_logger
from userdatamodel.driver import SQLAlchemyDriver
import random

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
        visa_type=None,
        concurrency=None,  # number of concurrent users going through the visa update flow
        thread_pool_size=None,  # number of Docker container CPU used for jwt verification
        buffer_size=None,  # max size of asyncio queue
    ):
        self.visa_type = visa_type or "ras"
        self.concurrency = concurrency or 3
        self.thread_pool_size = thread_pool_size or 2
        self.buffer_size = buffer_size or 10
        self.n_workers = self.thread_pool_size + self.concurrency

    async def update_tokens(self, db_session):
        """
        Have dictionary or something to decide which client to use. Can go through the whole list and decide which client to use
        looking at the type field in the ga4gh table.
        """
        queue = asyncio.Queue(maxsize=self.buffer_size)
        # producers = [asyncio.create_task(self.producer(i, db_session, queue)) for i in range(1)]
        producer = [
            asyncio.create_task(self.producer(db_session, queue, window_idx=0))
            for _ in range(1)
        ]
        workers = [asyncio.create_task(self.worker(j, queue)) for j in range(5)]

        await asyncio.gather(*producer)

        await queue.join()

        for w in workers:
            w.cancel()

    async def window(self, db_session, queue, window_idx):
        window_size = 8
        start, stop = window_size * window_idx, window_size * (window_idx + 1)
        visas = db_session.query(GA4GHVisaV1).slice(start, stop).all()

        return visas

    async def producer(self, db_session, queue, window_idx):
        """
        TODO: Rename this
        Producer: Produces users and puts them in a queue for processing

        """
        window_size = 8
        while True:
            visas = await self.window(db_session, queue, window_idx)
            if visas == None:
                break
            for visa in visas:
                print("Producer producing visa for user {}".format(visa.user.username))
                await queue.put(visa)
            if len(visas) < window_size:
                break
            window_idx += 1

    async def worker(self, name, queue):
        """
        TODO: Rename this
        worker: Create workers that does the visa update flow
        """
        # update visa stuff here
        while True:
            visa = await queue.get()
            client = self._pick_client(visa)
            username = visa.user.username
            user = visa.user
            # print("worker {} working on user {}".format(name, username))
            client.update_user_visas(user)
            await asyncio.sleep(random.random())
            queue.task_done()

    def _pick_client(self, visa):
        """
        Pick oidc client according to the visa provider
        """
        if visa.type == "https://ras/visa/v1":
            oidc = config.get("OPENID_CONNECT", {})
            return RASClient(
                oidc["ras"],
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
