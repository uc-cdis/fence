import asyncio

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


# Base class that collects only specific type of refresh token 


class Visa_Token_Update(object):

    def __init__(
        self,
        visa_type=None,
        concurrency=None, # number of concurrent users going through the visa update flow
        thread_pool_size=None, # number of Docker container CPU used for jwt verification
        buffer_size=None, # max size of asyncio queue
    ):
        self.visa_type = visa_type or "ras"
        self.concurrency = concurrency or 3
        self.thread_pool_size = thread_pool_size or 2
        self.buffer_size = buffer_size or 10
        self.n_workers = self.thread_pool_size + self.concurrency
        
    def update_tokens(self, db_session):
        """
        Have dictionary or something to decide which client to use. Can go through the whole list and decide which client to use 
        looking at the type field in the ga4gh table. 
        """

        queue = asyncio.Queue(maxsize=self.buffer_size)

        all_visas = db_session.query(GA4GHVisaV1).all()
        print("--------------------------------------------")
        for visa in all_visas:
            username = visa.user.username
            print(username)
            u = query_for_user(db_session, username)
            print(u.ga4gh_visas_v1)


        

    async def producer(self, queue):
        """
        TODO: Rename this
        Producer: Produces users and puts them in a queue for processing

        """
        # while there are users:
            # fill queue with users until queue is full 
            # could use a counter to query through each user in db and use this counter for Prometheus (???)

    async def consumer(self, queue):
        """
        TODO: Rename this
        Consumer: Create workers that does the visa update flow 
        """
        # update visa stuff here 